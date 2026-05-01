package main

import "go.uber.org/fx"

var version = "dev"

func main() {
	app := fx.New(
		fx.Provide(
			ProvideConfig,
			ProvideLogger,
			ProvideHTTPClient,
			ProvideOIDCManager,
			ProvideResponseCache,
			ProvideGRPCConnPool,
			ProvideDeps,
		),
		fx.Invoke(RunServer),
	)

	app.Run()
}
