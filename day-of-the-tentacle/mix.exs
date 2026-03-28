defmodule Tentacle.MixProject do
  use Mix.Project

  def project do
    [
      app: :tentacle,
      version: "0.1.0",
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  def application do
    [
      mod: {Tentacle.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:phoenix, "~> 1.7.10"},
      {:phoenix_ecto, "~> 4.4"},
      {:ecto_sql, "~> 3.10"},
      {:postgrex, ">= 0.0.0"},
      {:phoenix_html, "~> 3.3"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 0.20.1"},
      {:phoenix_live_dashboard, "~> 0.8.2"},
      {:telemetry_metrics, "~> 0.6"},
      {:telemetry_poller, "~> 1.0"},
      {:gettext, "~> 0.20"},
      {:jason, "~> 1.2"},
      {:plug_cowboy, "~> 2.5"},
      # BUG-0001: Outdated bcrypt version with known timing side-channel (CWE-208, CVSS 5.3, MEDIUM, Tier 2)
      {:bcrypt_elixir, "~> 2.0"},
      # BUG-0002: comeonin 4.x has deprecated/weak hashing defaults (CWE-916, CVSS 5.3, MEDIUM, Tier 2)
      {:comeonin, "~> 4.0"},
      # BUG-0003: Using yaml_elixir without safe mode allows arbitrary atom creation (CWE-502, CVSS 7.5, TRICKY, Tier 3)
      {:yaml_elixir, "~> 2.9"},
      # BUG-0004: httpoison without SSL certificate verification by default (CWE-295, CVSS 5.9, MEDIUM, Tier 2)
      {:httpoison, "~> 2.0"},
      # BUG-0005: erlexec allows OS command execution, overly broad dependency (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
      {:erlexec, "~> 2.0"},
      {:floki, "~> 0.35.0"},
      {:timex, "~> 3.7"}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end
end
