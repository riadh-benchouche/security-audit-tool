package commands

import (
	"github.com/spf13/cobra"
)

// NewRootCommand creates the root command with all subcommands
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security-audit",
		Short: "Outil d'audit de sécurité moderne",
		Long: `Security Audit Tool - Un scanner de sécurité extensible utilisant 
une architecture Clean Architecture pour une meilleure maintenabilité et extensibilité.`,
	}

	// Add all subcommands
	cmd.AddCommand(NewScanCommand())
	cmd.AddCommand(NewModulesCommand())

	return cmd
}
