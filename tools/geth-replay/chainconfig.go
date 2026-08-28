package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/params"
)

const (
	mainnetChainID   uint64 = 1
	avalancheChainID uint64 = 43114
)

type chainProfile struct {
	ID           uint64
	Name         string
	Experimental bool
}

func profileForChainID(chainID uint64) (chainProfile, error) {
	switch chainID {
	case mainnetChainID:
		return chainProfile{ID: chainID, Name: "ethereum-mainnet"}, nil
	case avalancheChainID:
		return chainProfile{ID: chainID, Name: "avalanche-c-chain", Experimental: true}, nil
	default:
		return chainProfile{}, fmt.Errorf("unsupported chain ID: %d", chainID)
	}
}

func getChainConfig(chainID uint64) (*params.ChainConfig, error) {
	profile, err := profileForChainID(chainID)
	if err != nil {
		return nil, err
	}
	if profile.ID == mainnetChainID {
		return params.MainnetChainConfig, nil
	}
	// The pinned go-ethereum version has no Avalanche profile. This provisional profile
	// changes only ChainID and inherits Mainnet fork rules; it is not paper-grade.
	config := *params.MainnetChainConfig
	config.ChainID = new(big.Int).SetUint64(avalancheChainID)
	return &config, nil
}
