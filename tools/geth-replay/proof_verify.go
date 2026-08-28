package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

type proofFile struct {
	Header struct {
		StateRoot string `json:"stateRoot"`
	} `json:"header"`
	Proofs []struct {
		Address string `json:"address"`
		Proof   struct {
			AccountProof []string `json:"accountProof"`
			StorageProof []struct {
				Key   string   `json:"key"`
				Proof []string `json:"proof"`
			} `json:"storageProof"`
			StorageHash string `json:"storageHash"`
		} `json:"proof"`
	} `json:"proofs"`
}

func addNodes(db ethdb.KeyValueWriter, nodes []string) error {
	for _, encoded := range nodes {
		node := common.Hex2Bytes(strings.TrimPrefix(encoded, "0x"))
		if len(node) == 0 {
			return fmt.Errorf("empty proof node")
		}
		if err := db.Put(crypto.Keccak256(node), node); err != nil {
			return err
		}
	}
	return nil
}

func verifyProofFile(path string) (int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var file proofFile
	if err := json.Unmarshal(data, &file); err != nil {
		return 0, 0, err
	}
	root := common.HexToHash(file.Header.StateRoot)
	accountsOK, storageOK := 0, 0
	for _, item := range file.Proofs {
		db := rawdb.NewMemoryDatabase()
		if err := addNodes(db, item.Proof.AccountProof); err != nil {
			return accountsOK, storageOK, err
		}
		value, err := trie.VerifyProof(root, crypto.Keccak256(common.HexToAddress(item.Address).Bytes()), db)
		if err != nil {
			return accountsOK, storageOK, fmt.Errorf("account %s: %w", item.Address, err)
		}
		accountsOK++
		if len(item.Proof.StorageProof) == 0 {
			continue
		}
		if value == nil {
			// eth_getProof may return requested storage keys even when the
			// account itself is absent.  The absent account has the canonical
			// empty storage trie, so every requested slot is zero.
			storageOK += len(item.Proof.StorageProof)
			continue
		}
		var fields []rlp.RawValue
		if err := rlp.DecodeBytes(value, &fields); err != nil || len(fields) != 4 {
			return accountsOK, storageOK, fmt.Errorf("account %s invalid rlp", item.Address)
		}
		var storageRoot common.Hash
		if err := rlp.DecodeBytes(fields[2], &storageRoot); err != nil {
			return accountsOK, storageOK, fmt.Errorf("account %s invalid storage root", item.Address)
		}
		for _, slot := range item.Proof.StorageProof {
			if storageRoot == types.EmptyRootHash {
				// The canonical empty storage trie has no proof nodes. A proof
				// for any slot is therefore the canonical zero value.
				storageOK++
				continue
			}
			sdb := rawdb.NewMemoryDatabase()
			if err := addNodes(sdb, slot.Proof); err != nil {
				return accountsOK, storageOK, err
			}
			if _, err := trie.VerifyProof(storageRoot, crypto.Keccak256(common.HexToHash(slot.Key).Bytes()), sdb); err != nil {
				return accountsOK, storageOK, fmt.Errorf("storage %s/%s: %w", item.Address, slot.Key, err)
			}
			storageOK++
		}
	}
	return accountsOK, storageOK, nil
}

// proofAccountExistence returns the authenticated account-presence bit for
// selected addresses.  A valid proof with a nil trie value means the account
// is absent, which is different from an existing empty account for EIP-7702
// gas accounting.
func proofAccountExistence(path string, addresses []string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file proofFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	wanted := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		wanted[strings.ToLower(common.HexToAddress(address).Hex())] = struct{}{}
	}
	result := make(map[string]bool, len(wanted))
	root := common.HexToHash(file.Header.StateRoot)
	for _, item := range file.Proofs {
		address := strings.ToLower(common.HexToAddress(item.Address).Hex())
		if _, ok := wanted[address]; !ok {
			continue
		}
		db := rawdb.NewMemoryDatabase()
		if err := addNodes(db, item.Proof.AccountProof); err != nil {
			return nil, err
		}
		value, err := trie.VerifyProof(root, crypto.Keccak256(common.HexToAddress(item.Address).Bytes()), db)
		if err != nil {
			return nil, fmt.Errorf("account %s: %w", item.Address, err)
		}
		result[address] = value != nil
	}
	for address := range wanted {
		if _, ok := result[address]; !ok {
			return nil, fmt.Errorf("proof missing required authorization account %s", address)
		}
	}
	return result, nil
}
