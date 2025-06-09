package commands

import (
	"fmt"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
	"strings"

	"github.com/riadh-benchouche/security-audit-tool/internal/application/handlers"
	"github.com/spf13/cobra"
)

// NewModulesCommand creates a command to list available modules
func NewModulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "modules",
		Short: "Liste les modules de scan disponibles",
		Long:  `Affiche la liste des modules de scan disponibles avec leurs informations.`,
		RunE:  runModulesCommand,
	}

	cmd.AddCommand(NewModuleInfoCommand())
	cmd.AddCommand(NewHealthCommand())

	return cmd
}

// runModulesCommand lists available modules
func runModulesCommand(cmd *cobra.Command, args []string) error {
	handler := handlers.NewScanHandler()

	fmt.Println("📦 Available Scan Modules")
	fmt.Println(strings.Repeat("=", 50))

	moduleInfos := handler.GetAllModuleInfos()
	if len(moduleInfos) == 0 {
		fmt.Println("❌ No modules available")
		return nil
	}

	for _, info := range moduleInfos {
		fmt.Printf("\n🔧 %s (v%s)\n", info.Name, info.Version)
		fmt.Printf("   📝 %s\n", info.Description)
		fmt.Printf("   👤 Author: %s\n", info.Author)

		if len(info.Capabilities) > 0 {
			fmt.Printf("   ⚡ Capabilities: %s\n", strings.Join(info.Capabilities, ", "))
		}

		if len(info.Tags) > 0 {
			fmt.Printf("   🏷️  Tags: %s\n", strings.Join(info.Tags, ", "))
		}
	}

	fmt.Printf("\n💡 Usage: security-audit scan -t <target> -m %s\n",
		strings.Join(getModuleNames(moduleInfos), ","))

	return nil
}

// NewModuleInfoCommand creates a command to show detailed module information
func NewModuleInfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info [module-name]",
		Short: "Affiche les informations détaillées d'un module",
		Args:  cobra.ExactArgs(1),
		RunE:  runModuleInfoCommand,
	}

	return cmd
}

// runModuleInfoCommand shows detailed module information
func runModuleInfoCommand(cmd *cobra.Command, args []string) error {
	moduleName := args[0]
	handler := handlers.NewScanHandler()

	info, err := handler.GetModuleInfo(moduleName)
	if err != nil {
		return fmt.Errorf("module '%s' not found", moduleName)
	}

	fmt.Printf("📦 Module: %s\n", info.Name)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Version:     %s\n", info.Version)
	fmt.Printf("Description: %s\n", info.Description)
	fmt.Printf("Author:      %s\n", info.Author)

	if info.Website != "" {
		fmt.Printf("Website:     %s\n", info.Website)
	}

	if info.License != "" {
		fmt.Printf("License:     %s\n", info.License)
	}

	if len(info.Capabilities) > 0 {
		fmt.Printf("\n⚡ Capabilities:\n")
		for _, cap := range info.Capabilities {
			fmt.Printf("  • %s\n", cap)
		}
	}

	if len(info.Tags) > 0 {
		fmt.Printf("\n🏷️  Tags: %s\n", strings.Join(info.Tags, ", "))
	}

	if len(info.ConfigSchema) > 0 {
		fmt.Printf("\n⚙️  Configuration Options:\n")
		for key, schema := range info.ConfigSchema {
			fmt.Printf("  • %s: %s\n", key, schema)
		}
	}

	return nil
}

// NewHealthCommand creates a command to check scanner health
func NewHealthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Vérifie l'état de santé des modules",
		RunE:  runHealthCommand,
	}

	return cmd
}

// runHealthCommand checks and displays scanner health
func runHealthCommand(cmd *cobra.Command, args []string) error {
	handler := handlers.NewScanHandler()

	fmt.Println("🏥 Scanner Health Check")
	fmt.Println(strings.Repeat("=", 40))

	healthStatuses := handler.HealthCheck()

	allHealthy := true
	for name, status := range healthStatuses {
		icon := "✅"
		if status.Status != "healthy" {
			icon = "❌"
			allHealthy = false
		}

		fmt.Printf("%s %s: %s\n", icon, name, status.Status)

		if status.Message != "" {
			fmt.Printf("   📝 %s\n", status.Message)
		}

		if len(status.Errors) > 0 {
			fmt.Printf("   ⚠️  Errors:\n")
			for _, err := range status.Errors {
				fmt.Printf("      • %s\n", err)
			}
		}
	}

	fmt.Println(strings.Repeat("-", 40))
	if allHealthy {
		fmt.Println("🎉 All modules are healthy!")
	} else {
		fmt.Println("⚠️  Some modules have issues. Check the details above.")
	}

	return nil
}

// getModuleNames extracts module names from module infos
func getModuleNames(moduleInfos map[string]*interfaces.ScannerInfo) []string {
	names := make([]string, 0, len(moduleInfos))
	for name := range moduleInfos {
		names = append(names, name)
	}
	return names
}
