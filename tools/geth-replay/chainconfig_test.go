package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/params"
)

func TestGetChainConfigMainnet(t *testing.T) {
	config, err := getChainConfig(mainnetChainID)
	if err != nil {
		t.Fatal(err)
	}
	if config != params.MainnetChainConfig {
		t.Fatal("mainnet must retain the standard go-ethereum config")
	}
	if !config.IsPrague(new(big.Int).SetUint64(25716150), 1786263167) {
		t.Fatal("USM block must execute under Prague rules")
	}
	if !config.IsBPO2(new(big.Int).SetUint64(25716150), 1786263167) {
		t.Fatal("USM block must execute under the configured BPO2 blob schedule")
	}
}

func TestGetChainConfigAvalanche(t *testing.T) {
	config, err := getChainConfig(avalancheChainID)
	if err != nil {
		t.Fatal(err)
	}
	if config.ChainID.Cmp(new(big.Int).SetUint64(avalancheChainID)) != 0 {
		t.Fatalf("unexpected chain ID: %s", config.ChainID)
	}
	profile, err := profileForChainID(avalancheChainID)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Experimental {
		t.Fatal("Avalanche profile must remain experimental")
	}
}

func TestGetChainConfigRejectsUnsupportedChain(t *testing.T) {
	if _, err := getChainConfig(999); err == nil {
		t.Fatal("unsupported chain ID must fail closed")
	}
	if _, err := profileForChainID(999); err == nil {
		t.Fatal("unsupported chain profile must fail closed")
	}
}
