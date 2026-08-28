package main

// B2 baseline probe: execute each transaction with go-ethereum's real EVM
// using that transaction's own prestateTracer snapshot.  This first milestone
// is intentionally labelled "prestate-isolated": it validates chain rules,
// header fields, and per-transaction gas/status before we add a sequential
// state builder.  It must not be mistaken for the final prefix replayer.

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

type row struct {
	Index int             `json:"index"`
	Hash  string          `json:"tx_hash"`
	Trace json.RawMessage `json:"trace"`
}

type account struct {
	Balance string            `json:"balance"`
	Nonce   uint64            `json:"nonce"`
	Code    string            `json:"code"`
	Storage map[string]string `json:"storage"`
	// Exists is populated for accounts whose authenticated proof distinguishes
	// an absent account from an EIP-161-empty account.  That distinction affects
	// EIP-7702's state-dependent gas refund.
	Exists *bool `json:"exists,omitempty"`
}

const goEthereumVersion = "v1.17.5"

func mergeAccounts(rows []row) (map[string]account, error) {
	merged := make(map[string]account)
	seenNonce := make(map[string]bool)
	for _, item := range rows {
		var incoming map[string]account
		if err := json.Unmarshal(item.Trace, &incoming); err != nil {
			return nil, err
		}
		for address, value := range incoming {
			current := merged[address]
			if current.Balance == "" && value.Balance != "" {
				current.Balance = value.Balance
			}
			if current.Code == "" && value.Code != "" {
				current.Code = value.Code
			}
			if !seenNonce[address] {
				current.Nonce = value.Nonce
				seenNonce[address] = true
			}
			if current.Storage == nil {
				current.Storage = make(map[string]string)
			}
			for slot, storageValue := range value.Storage {
				if _, exists := current.Storage[slot]; !exists {
					current.Storage[slot] = storageValue
				}
			}
			if value.Exists != nil {
				current.Exists = value.Exists
			}
			merged[address] = current
		}
	}
	return merged, nil
}

func authorizationAddresses(txs []types.Transaction) (map[string][]string, error) {
	authorities := make(map[string]struct{})
	codeTargets := make(map[string]struct{})
	for _, tx := range txs {
		for _, authorization := range tx.SetCodeAuthorizations() {
			authority, err := authorization.Authority()
			if err != nil {
				return nil, fmt.Errorf("recover EIP-7702 authority for %s: %w", tx.Hash(), err)
			}
			authorities[strings.ToLower(authority.Hex())] = struct{}{}
			codeTargets[strings.ToLower(authorization.Address.Hex())] = struct{}{}
		}
	}
	toSorted := func(values map[string]struct{}) []string {
		addresses := make([]string, 0, len(values))
		for address := range values {
			addresses = append(addresses, address)
		}
		sort.Strings(addresses)
		return addresses
	}
	required := make(map[string]struct{}, len(authorities)+len(codeTargets))
	for address := range authorities {
		required[address] = struct{}{}
	}
	for address := range codeTargets {
		required[address] = struct{}{}
	}
	return map[string][]string{
		"authorities":  toSorted(authorities),
		"code_targets": toSorted(codeTargets),
		"required":     toSorted(required),
	}, nil
}

type result struct {
	Index          int             `json:"index"`
	Hash           string          `json:"tx_hash"`
	ExpectedGas    uint64          `json:"expected_gas"`
	ActualGas      uint64          `json:"actual_gas"`
	GasMatch       bool            `json:"gas_match"`
	ExpectedOK     bool            `json:"expected_status"`
	ActualOK       bool            `json:"actual_status"`
	StatusMatch    bool            `json:"status_match"`
	Error          string          `json:"error,omitempty"`
	RevertData     string          `json:"revert_data,omitempty"`
	CallTrace      []callFrame     `json:"call_trace,omitempty"`
	Logs           []*types.Log    `json:"logs,omitempty"`
	BalanceChanges []balanceChange `json:"balance_changes,omitempty"`
	OpcodeTail     []opcodeEvent   `json:"opcode_tail,omitempty"`
}

type balanceChange struct {
	Address  string `json:"address"`
	Previous string `json:"previous"`
	Current  string `json:"current"`
}

type callFrame struct {
	Event    string `json:"event"`
	Depth    int    `json:"depth"`
	Type     string `json:"type,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Input    string `json:"input,omitempty"`
	Gas      uint64 `json:"gas,omitempty"`
	Value    string `json:"value,omitempty"`
	GasUsed  uint64 `json:"gas_used,omitempty"`
	Error    string `json:"error,omitempty"`
	Reverted bool   `json:"reverted,omitempty"`
}

type opcodeEvent struct {
	PC    uint64 `json:"pc"`
	Op    string `json:"op"`
	Gas   uint64 `json:"gas"`
	Cost  uint64 `json:"cost"`
	Depth int    `json:"depth"`
	Error string `json:"error,omitempty"`
}

func targetLogs(all []*types.Log, prefixCount int) []*types.Log {
	if prefixCount < 0 || prefixCount > len(all) {
		return nil
	}
	return append([]*types.Log(nil), all[prefixCount:]...)
}

func newCallHooks() (*tracing.Hooks, *[]callFrame, *string, *[]balanceChange, *[]*types.Log, *[]opcodeEvent) {
	frames := make([]callFrame, 0)
	revertData := ""
	balanceChanges := make([]balanceChange, 0)
	logs := make([]*types.Log, 0)
	opcodes := make([]opcodeEvent, 0)
	hooks := &tracing.Hooks{
		OnEnter: func(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
			frames = append(frames, callFrame{Event: "enter", Depth: depth,
				Type: vm.OpCode(typ).String(), From: from.Hex(), To: to.Hex(),
				Input: hexutil.Encode(input), Gas: gas, Value: value.String()})
		},
		OnExit: func(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
			frame := callFrame{Event: "exit", Depth: depth, GasUsed: gasUsed, Reverted: reverted}
			if err != nil {
				frame.Error = err.Error()
			}
			if depth == 0 && reverted && len(output) > 0 {
				revertData = hexutil.Encode(output)
			}
			frames = append(frames, frame)
		},
		OnBalanceChange: func(addr common.Address, previous, current *big.Int, _ tracing.BalanceChangeReason) {
			balanceChanges = append(balanceChanges, balanceChange{Address: addr.Hex(), Previous: previous.String(), Current: current.String()})
		},
		OnLog: func(log *types.Log) { logs = append(logs, log) },
	}
	hooks.OnOpcode = func(pc uint64, op byte, gas, cost uint64, _ tracing.OpContext, _ []byte, depth int, err error) {
		e := opcodeEvent{PC: pc, Op: vm.OpCode(op).String(), Gas: gas, Cost: cost, Depth: depth}
		if err != nil {
			e.Error = err.Error()
		}
		if len(opcodes) >= 128 {
			opcodes = opcodes[1:]
		}
		opcodes = append(opcodes, e)
	}
	return hooks, &frames, &revertData, &balanceChanges, &logs, &opcodes
}

type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }
func (f *stringListFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type output struct {
	Mode                  string         `json:"mode"`
	ChainRules            map[string]any `json:"chain_rules"`
	BlockNumber           string         `json:"block_number"`
	Results               []result       `json:"per_tx"`
	TotalGas              uint64         `json:"total_actual_gas"`
	TotalExpect           uint64         `json:"total_expected_gas"`
	AllGasMatch           bool           `json:"all_gas_match"`
	AllStatus             bool           `json:"all_status_match"`
	IsolatedGate          bool           `json:"isolated_baseline_gate"`
	StateRoot             string         `json:"state_root_actual"`
	ExpectedRoot          string         `json:"state_root_expected"`
	StateRootMatch        bool           `json:"state_root_match"`
	PrestateProofVerified bool           `json:"prestate_proof_verified"`
	ProofAccounts         int            `json:"proof_accounts_verified"`
	ProofStorage          int            `json:"proof_storage_cells_verified"`
	TargetIndex           int            `json:"target_index"`
	PrefixGasMatch        bool           `json:"prefix_gas_match"`
	Mutation              bool           `json:"mutation"`
	MutationNote          string         `json:"mutation_note,omitempty"`
	Acceptance            bool           `json:"acceptance_gate"`
	Note                  string         `json:"note"`
}

type chainContext struct {
	header *types.Header
	config *params.ChainConfig
}

func (c chainContext) Engine() consensus.Engine { return nil }

func (c chainContext) CurrentHeader() *types.Header { return c.header }

func (c chainContext) GetHeader(_ common.Hash, number uint64) *types.Header {
	if c.header != nil && c.header.Number.Uint64() == number {
		return c.header
	}
	return nil
}

func (c chainContext) GetHeaderByHash(hash common.Hash) *types.Header {
	if c.header != nil && c.header.Hash() == hash {
		return c.header
	}
	return nil
}

func (c chainContext) GetHeaderByNumber(number uint64) *types.Header {
	return c.GetHeader(common.Hash{}, number)
}

func (c chainContext) Config() *params.ChainConfig { return c.config }

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func quantity(s string) *big.Int {
	s = strings.TrimSpace(s)
	if s == "" || s == "0x" {
		return new(big.Int)
	}
	n := new(big.Int)
	if strings.HasPrefix(s, "0x") {
		n.SetString(s[2:], 16)
	} else {
		n.SetString(s, 10)
	}
	return n
}

func makeState(accounts map[string]account) (*state.StateDB, error) {
	disk := rawdb.NewMemoryDatabase()
	trie := triedb.NewDatabase(disk, nil)
	db := state.NewDatabase(trie, nil)
	st, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		return nil, err
	}
	for address, a := range accounts {
		addr := common.HexToAddress(address)
		if a.Exists != nil && !*a.Exists {
			// Do not materialize an authenticated absent account.  In particular,
			// EIP-7702 applies a different refund when the authority existed at
			// transaction start, so CreateAccount here would change gas semantics.
			continue
		}
		st.CreateAccount(addr)
		st.SetNonce(addr, a.Nonce, tracing.NonceChangeUnspecified)
		st.SetBalance(addr, uint256.MustFromBig(quantity(a.Balance)), tracing.BalanceChangeUnspecified)
		if a.Code != "" && a.Code != "0x" {
			code, err := hexutil.Decode(a.Code)
			if err != nil {
				return nil, err
			}
			st.SetCode(addr, code, tracing.CodeChangeUnspecified)
		}
		for slot, value := range a.Storage {
			st.SetState(addr, common.HexToHash(slot), common.HexToHash(value))
		}
	}
	// SSTORE gas/refund rules depend on the committed/original storage value,
	// not only on StateDB's dirty overlay.  Commit the injected snapshot and
	// reopen it so the EVM sees these values as historical state.
	root, err := st.Commit(0, false, false)
	if err != nil {
		return nil, err
	}
	return state.New(root, db)
}

func parseOverride(value string) (common.Address, string, error) {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return common.Address{}, "", fmt.Errorf("override must be address=value: %s", value)
	}
	return common.HexToAddress(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1]), nil
}

func replaceLegacyData(tx types.Transaction, data string) (types.Transaction, error) {
	if tx.Type() != types.LegacyTxType {
		return types.Transaction{}, fmt.Errorf("target-data only supports legacy transactions")
	}
	v, r, s := tx.RawSignatureValues()
	decoded, err := hexutil.Decode(data)
	if err != nil {
		return types.Transaction{}, err
	}
	return *types.NewTx(&types.LegacyTx{
		Nonce: tx.Nonce(), GasPrice: tx.GasPrice(), Gas: tx.Gas(),
		To: tx.To(), Value: tx.Value(), Data: decoded, V: v, R: r, S: s,
	}), nil
}

func main() {
	context := flag.String("context", "", "B2 context directory")
	outputPath := flag.String("output", "", "output JSON")
	listAuthorities := flag.Bool("list-authorities", false, "print recovered EIP-7702 authorities and exit")
	chainID := flag.Uint64("chain-id", mainnetChainID, "chain ID (1=Ethereum Mainnet, 43114=experimental Avalanche C-Chain)")
	proofPath := flag.String("proofs", "", "prestate_proofs.json (optional)")
	targetIndex := flag.Int("target-index", -1, "target transaction index; defaults to last")
	targetData := flag.String("target-data", "", "replacement calldata for target legacy tx")
	var targetCode stringListFlag
	var targetStorage stringListFlag
	flag.Var(&targetCode, "target-code", "address=runtime-bytecode override (repeatable)")
	flag.Var(&targetStorage, "target-storage", "address:slot=value override (repeatable)")
	flag.Parse()
	chainProfile, err := profileForChainID(*chainID)
	if err != nil {
		panic(err)
	}
	chainConfig, err := getChainConfig(*chainID)
	if err != nil {
		panic(err)
	}
	if *context == "" || (!*listAuthorities && *outputPath == "") {
		panic("--context is required; --output is required unless --list-authorities is used")
	}
	var header types.Header
	if err := readJSON(*context+"/block.json", &header); err != nil {
		panic(err)
	}
	var txs []types.Transaction
	var rawTxs []json.RawMessage
	if err := readJSON(*context+"/transactions.json", &rawTxs); err != nil {
		panic(err)
	}
	for _, raw := range rawTxs {
		var tx types.Transaction
		if err := tx.UnmarshalJSON(raw); err != nil {
			panic(err)
		}
		txs = append(txs, tx)
	}
	if *listAuthorities {
		addresses, err := authorizationAddresses(txs)
		if err != nil {
			panic(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
			"go_ethereum_version": goEthereumVersion,
			"authorities":         addresses["authorities"],
			"code_targets":        addresses["code_targets"],
			"required_accounts":   addresses["required"],
		}); err != nil {
			panic(err)
		}
		return
	}
	var receipts []struct {
		Index   int    `json:"index"`
		TxHash  string `json:"tx_hash"`
		Receipt struct {
			Status  string `json:"status"`
			GasUsed string `json:"gasUsed"`
		} `json:"receipt"`
	}
	if err := readJSON(*context+"/receipts.json", &receipts); err != nil {
		panic(err)
	}
	var traces []row
	if err := readJSON(*context+"/prestates.json", &traces); err != nil {
		panic(err)
	}
	if len(txs) != len(receipts) || len(txs) != len(traces) {
		panic("context counts do not match")
	}
	if *targetIndex < 0 {
		*targetIndex = len(txs) - 1
	}
	if *targetIndex < 0 || *targetIndex >= len(txs) {
		panic("target-index outside context")
	}
	merged, err := mergeAccounts(traces)
	if err != nil {
		panic(err)
	}
	if authPath := *context + "/authorization_accounts.json"; fileExists(authPath) {
		var authAccounts map[string]account
		if err := readJSON(authPath, &authAccounts); err != nil {
			panic(err)
		}
		authPayload, err := json.Marshal(authAccounts)
		if err != nil {
			panic(err)
		}
		merged, err = mergeAccounts(append(traces, row{Trace: authPayload}))
		if err != nil {
			panic(err)
		}
	}
	if *proofPath != "" {
		authAddresses, err := authorizationAddresses(txs)
		if err != nil {
			panic(err)
		}
		existence, err := proofAccountExistence(*proofPath, authAddresses["required"])
		if err != nil {
			panic(err)
		}
		for address, exists := range existence {
			a := merged[address]
			a.Exists = &exists
			merged[address] = a
		}
	}
	st, err := makeState(merged)
	if err != nil {
		panic(err)
	}
	gasPool := core.NewGasPool(header.GasLimit)

	rules := chainConfig.Rules(header.Number, false, header.Time)
	resultOutput := output{Mode: "sequential-relevant-substate", BlockNumber: header.Number.String(), ChainRules: map[string]any{
		"chain_id": chainProfile.ID, "chain_name": chainProfile.Name,
		"go_ethereum_version": goEthereumVersion,
		"experimental":        chainProfile.Experimental,
		"istanbul":            rules.IsIstanbul, "berlin": rules.IsBerlin, "london": rules.IsLondon,
		"header_time": header.Time, "header_gas_limit": header.GasLimit,
		"difficulty": header.Difficulty.String(), "base_fee_nil": header.BaseFee == nil,
	}, AllGasMatch: true, AllStatus: true, TargetIndex: *targetIndex,
		Note: "One shared StateDB; initial values are the union of transaction-relevant prestate snapshots. Global state root is out of scope; local prestate Merkle proofs are the authenticity gate."}
	resultOutput.Mutation = *targetData != "" || len(targetCode) > 0 || len(targetStorage) > 0
	if resultOutput.Mutation {
		resultOutput.MutationNote = "target override applied after prefix transactions"
	}
	targetPrefixLogCount := -1
	for i, tx := range txs[:*targetIndex+1] {
		if i == *targetIndex && *targetData != "" {
			tx, err = replaceLegacyData(tx, *targetData)
			if err != nil {
				resultOutput.Results = append(resultOutput.Results, result{Index: i, Hash: tx.Hash().Hex(), Error: err.Error()})
				resultOutput.AllGasMatch = false
				resultOutput.AllStatus = false
				continue
			}
		}
		if i == *targetIndex {
			// StateDB accumulates logs from the sequential prefix and target.
			// Record the prefix length before applying the target so output
			// contains only logs emitted by this transaction.
			targetPrefixLogCount = len(st.Logs())
			for _, item := range targetCode {
				address, code, parseErr := parseOverride(item)
				if parseErr != nil {
					panic(parseErr)
				}
				decoded, decodeErr := hexutil.Decode(code)
				if decodeErr != nil {
					panic(decodeErr)
				}
				st.SetCode(address, decoded, tracing.CodeChangeUnspecified)
			}
			for _, item := range targetStorage {
				parts := strings.SplitN(item, "=", 2)
				if len(parts) != 2 {
					panic("target-storage must be address:slot=value")
				}
				left := strings.SplitN(parts[0], ":", 2)
				if len(left) != 2 {
					panic("target-storage must be address:slot=value")
				}
				st.SetState(common.HexToAddress(left[0]), common.HexToHash(left[1]), common.HexToHash(parts[1]))
			}
		}
		var expectedGas *big.Int
		var expectedOK bool
		expectedGas = quantity(receipts[i].Receipt.GasUsed)
		expectedOK = receipts[i].Receipt.Status == "0x1"
		r := result{Index: i, Hash: tx.Hash().Hex(), ExpectedGas: expectedGas.Uint64(), ExpectedOK: expectedOK}
		var runErr error
		if err == nil {
			config := vm.Config{}
			var frames *[]callFrame
			var revertData *string
			var balanceChanges *[]balanceChange
			var logs *[]*types.Log
			var opcodes *[]opcodeEvent
			if i == *targetIndex {
				var hooks *tracing.Hooks
				hooks, frames, revertData, balanceChanges, logs, opcodes = newCallHooks()
				config.Tracer = hooks
			}
			blockContext := core.NewEVMBlockContext(&header, chainContext{header: &header, config: chainConfig}, &header.Coinbase)
			evm := vm.NewEVM(blockContext, st, chainConfig, config)
			receipt, _, applyErr := core.ApplyTransaction(evm, gasPool, st, &header, &tx)
			if applyErr != nil {
				runErr = applyErr
			} else {
				r.ActualGas = receipt.GasUsed
				r.ActualOK = receipt.Status == types.ReceiptStatusSuccessful
			}
			if frames != nil {
				r.CallTrace = *frames
			}
			if revertData != nil {
				r.RevertData = *revertData
			}
			if balanceChanges != nil {
				r.BalanceChanges = *balanceChanges
			}
			if logs != nil {
				r.Logs = *logs
			}
			if i == *targetIndex && receipt != nil && targetPrefixLogCount >= 0 {
				r.Logs = targetLogs(st.Logs(), targetPrefixLogCount)
			}
			if opcodes != nil {
				r.OpcodeTail = *opcodes
			}
		}
		if runErr != nil {
			r.Error = runErr.Error()
			r.GasMatch = false
			r.StatusMatch = false
		} else {
			r.GasMatch = r.ActualGas == r.ExpectedGas
			r.StatusMatch = r.ActualOK == r.ExpectedOK
		}
		resultOutput.Results = append(resultOutput.Results, r)
		resultOutput.TotalGas += r.ActualGas
		resultOutput.TotalExpect += r.ExpectedGas
		resultOutput.AllGasMatch = resultOutput.AllGasMatch && r.GasMatch
		resultOutput.AllStatus = resultOutput.AllStatus && r.StatusMatch
	}
	resultOutput.PrefixGasMatch = true
	for i, r := range resultOutput.Results {
		if i < *targetIndex {
			resultOutput.PrefixGasMatch = resultOutput.PrefixGasMatch && r.GasMatch && r.StatusMatch
		}
	}
	resultOutput.IsolatedGate = resultOutput.AllGasMatch && resultOutput.AllStatus && len(resultOutput.Results) == len(txs)
	root := st.IntermediateRoot(false)
	resultOutput.StateRoot = root.Hex()
	resultOutput.ExpectedRoot = header.Root.Hex()
	resultOutput.StateRootMatch = root == header.Root
	if *proofPath != "" {
		accountsOK, storageOK, proofErr := verifyProofFile(*proofPath)
		resultOutput.ProofAccounts = accountsOK
		resultOutput.ProofStorage = storageOK
		resultOutput.PrestateProofVerified = proofErr == nil
		if proofErr != nil {
			resultOutput.Note += " proof verification failed: " + proofErr.Error()
		}
	}
	// Global state root is out of scope for a transaction-relevant snapshot.
	resultOutput.Acceptance = resultOutput.AllGasMatch && resultOutput.AllStatus && resultOutput.PrestateProofVerified && len(resultOutput.Results) == len(txs)
	b, _ := json.MarshalIndent(resultOutput, "", "  ")
	if err := os.WriteFile(*outputPath, append(b, '\n'), 0644); err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
