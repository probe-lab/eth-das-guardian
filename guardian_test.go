package dasguardian

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testBeaconAPI = "https://beacon.fusaka-devnet-2.ethpandaops.io/"
)

func Test_DASGuardianClientInterop(t *testing.T) {
	clients := map[string]string{
		"lighthouse": "enr:-PO4QFAZca5TDfbiiCKouERBRao_oLgy5KCPvbezPfhTacxHWlBqfDgsfsghRLBUH9W8bj08v1jkd64UoUjSaWZx-6UHh2F0dG5ldHOIAAAAAAADAACDY2djgYCGY2xpZW502IpMaWdodGhvdXNljDcuMS4wLWJldGEuMIRldGgykIEAExpwk3VEAAEAAAAAAACCaWSCdjSCaXCEn99xd4NuZmSENp-J94RxdWljgiMpiXNlY3AyNTZrMaEDzVa77_o452OzzqylcK2mA0DREidLotbGonvz3nogDS-Ic3luY25ldHMPg3RjcIIjKIN1ZHCCIyg",
		"prysm":      "enr:-Nm4QC89gsJ5_ndVJmiICaZpuebe7ppJbq2Y8Fz7xmICUCr3PYxIId-1hGLhP3cc7PwibKyQKcx2YNmCouMHH_QDXNaGAZesHoZVh2F0dG5ldHOIAAAAAAAAAAODY2djgYCEZXRoMpCBABMacJN1RAABAAAAAAAAgmlkgnY0gmlwhKdHVViDbmZkhDafifeEcXVpY4IyyIlzZWNwMjU2azGhAqi72ZtElLUzVdd7OdFlAFOjeCeQcoCGc8mugYAxD71tiHN5bmNuZXRzB4N0Y3CCIyiDdWRwgiMo",
		"teku":       "enr:-Mu4QMDbGc5XAr9gHNuxzh3SMuAPlZgb92ANxqW_l0yj5rG9TFw-8WtV5Ce5GIrwVuXFKatMf7sEo8vPk-D5Ag0lx5kLh2F0dG5ldHOIAAAAAAAAAwCDY2djgYCEZXRoMpCBABMacJN1RAABAAAAAAAAgmlkgnY0gmlwhLI-9cGDbmZkhDafifeJc2VjcDI1NmsxoQJczuIuEAkKdvHogN6dxbIwveUYkCXAm6yuukurgpPSnIhzeW5jbmV0cw-DdGNwgiMog3VkcIIjKA",
		"nimbus":     "enr:-MK4QBgpjUnYMj6Pb5LP7pwe8dAe4BOQFSyS6KrjGlp0gyugAKAXQFb4dYl_mQOLCgTAo5FGWT7hARPBaOKy2dyDJ0QEh2F0dG5ldHOIAIABAAAAAACDY2djgYCEZXRoMpCBABMacJN1RAABAAAAAAAAgmlkgnY0gmlwhIbHooWJc2VjcDI1NmsxoQM-ZoNHP9Shg_xnnig6etGeMzfC1N0mLiVWCguePKnBTIhzeW5jbmV0cwuDdGNwgiMog3VkcIIjKA",
		"lodestar":   "enr:-Mq4QF5K5FTqB02r-s-1zPyYrZA7FijHYCbo85mZroTpe21aKv7rsvkGdcZ5mLf08mFQEj_HKpP9_FOOfJwkOpjihSgIh2F0dG5ldHOIDAAAAAAAAACDY2djCIRldGgykIEAExpwk3VEAAEAAAAAAACCaWSCdjSCaXCEiztN34NuZmSENp-J94lzZWNwMjU2azGhA3d-BAO9NxwoQ7qg5jCUZb-MBb91LNYlO8eaoLU3shP4iHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo",
		"grandine":   "enr:-PG4QOcDgNnDfDDOhNcpxWxtlUUu7HyT0KOX4XWnqIwEmBJ-Ek_yVoknbtVGuGVi0HLSONGizfUsiPXi9981Z-ZOu_sJh2F0dG5ldHOIAAMAAAAAAACDY2djCIZjbGllbnTXiEdyYW5kaW5ljTEuMS4xLTU1OTIzYjmEZXRoMpCBABMacJN1RAABAAAAAAAAgmlkgnY0gmlwhC5llUaDbmZkhDafifeEcXVpY4IjKYlzZWNwMjU2azGhA11dnrjCPJFjsyHhXRrgV7wJodrGFgiSGb4GCLWy8UkRiHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo",
	}

	for client, enr := range clients {
		client := client
		enr := enr
		t.Run(fmt.Sprintf("client=%s", client), func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			guardian := genBasicGuardian(t, testCtx)

			ethNode, err := ParseNode(enr)
			require.NoError(t, err, "enr parsing failed for client %s", client)

			_, err = guardian.Scan(testCtx, ethNode)
			require.NoError(t, err, "interop test failed for client %s", client)
		})
	}
}

// genBasicGuardian initializes a test guardian instance.
func genBasicGuardian(t *testing.T, ctx context.Context) *DasGuardian {
	cfg := &DasGuardianConfig{
		Libp2pHost:        "127.0.0.1",
		Libp2pPort:        9020,
		ConnectionRetries: 2,
		ConnectionTimeout: 30 * time.Second,
		BeaconAPIendpoint: testBeaconAPI,
		WaitForFulu:       true,
	}

	guardian, err := NewDASGuardian(ctx, cfg)
	require.NoError(t, err)
	return guardian
}
