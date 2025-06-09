package commands

import (
	"context"
	"fmt"
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"strings"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/application/commands"
	"github.com/riadh-benchouche/security-audit-tool/internal/application/dto"
	"github.com/riadh-benchouche/security-audit-tool/internal/application/handlers"
	"github.com/riadh-benchouche/security-audit-tool/internal/infrastructure/logging"
	"github.com/riadh-benchouche/security-audit-tool/internal/interfaces/output"
	"github.com/spf13/cobra"
)

// ScanCommand handles the scan CLI command
type ScanCommand struct {
	handler      *handlers.ScanHandler
	outputFormat string
	outputFile   string
	verbose      bool
	timeout      int
	target       string
	modules      []string
}

// NewScanCommand creates a new scan command
func NewScanCommand() *cobra.Command {
	sc := &ScanCommand{
		handler: handlers.NewScanHandler(),
	}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Lance un scan de sécurité",
		Long:  `Lance un scan de sécurité sur la cible spécifiée avec les modules sélectionnés.`,
		RunE:  sc.runScan,
	}

	// Flags
	cmd.Flags().StringVarP(&sc.target, "target", "t", "", "cible à scanner (IP, domaine, ou URL)")
	cmd.Flags().StringSliceVarP(&sc.modules, "modules", "m", []string{"network"}, "modules à utiliser (network,http)")
	cmd.Flags().StringVarP(&sc.outputFormat, "format", "f", "text", "format de sortie (text, json, html)")
	cmd.Flags().StringVarP(&sc.outputFile, "output", "o", "", "fichier de sortie")
	cmd.Flags().BoolVarP(&sc.verbose, "verbose", "v", false, "sortie détaillée")
	cmd.Flags().IntVar(&sc.timeout, "timeout", 300, "timeout en secondes")

	// Mark required flags
	cmd.MarkFlagRequired("target")

	return cmd
}

// runScan executes the scan command
func (sc *ScanCommand) runScan(cmd *cobra.Command, args []string) error {
	// Setup logger
	logger := logging.NewLogger(sc.verbose)
	logger.Info("🔍 Security Audit Tool - Starting scan", map[string]interface{}{
		"target":  sc.target,
		"modules": sc.modules,
	})

	// Create scan command
	scanCmd := &commands.StartScanCommand{
		Target:    sc.target,
		Modules:   sc.modules,
		CreatedBy: "cli-user",
		Options: map[string]interface{}{
			"timeout": sc.timeout,
			"verbose": sc.verbose,
		},
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(sc.timeout)*time.Second)
	defer cancel()

	// Execute scan
	logger.Info("🚀 Executing scan...", nil)
	result, err := sc.handler.HandleStartScan(ctx, scanCmd)
	if err != nil {
		logger.Error("❌ Scan failed", err, nil)
		return fmt.Errorf("scan failed: %w", err)
	}

	// Convert to DTO for output
	scanResponse := dto.ToScanResponse(result.Scan)

	// Handle output
	outputHandler := output.NewOutputHandler()
	outputHandler.SetFormat(output.OutputFormat(sc.outputFormat))

	if sc.outputFile != "" {
		// Save to file
		if !strings.HasPrefix(sc.outputFile, "results/") && !strings.HasPrefix(sc.outputFile, "/") && !strings.Contains(sc.outputFile, ":") {
			sc.outputFile = "results/" + sc.outputFile
		}

		err = outputHandler.SaveToFile(scanResponse, sc.outputFile)
		if err != nil {
			logger.Error("❌ Failed to save results", err, map[string]interface{}{
				"output_file": sc.outputFile,
			})
			return fmt.Errorf("failed to save results: %w", err)
		}

		logger.Info("💾 Results saved", map[string]interface{}{
			"file": sc.outputFile,
		})
	} else {
		// Print to console
		outputHandler.PrintToConsole(scanResponse)
	}

	// Print summary
	sc.printScanSummary(result, logger)

	return nil
}

// printScanSummary prints a summary of the scan results
func (sc *ScanCommand) printScanSummary(result *commands.StartScanResult, logger *logging.Logger) {
	scan := result.Scan

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                 SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("📊 Status:        %s\n", scan.Status().String())
	fmt.Printf("🎯 Target:        %s\n", scan.Target().Original())
	fmt.Printf("⏱️ Duration:      %s\n", scan.Duration().String())
	fmt.Printf("🔍 Total Findings: %d\n", len(scan.GetAllFindings()))

	if scan.Summary() != nil {
		summary := scan.Summary()
		fmt.Printf("📈 Score:         %d/100 (Grade: %s)\n", summary.Score(), summary.Grade())
		fmt.Printf("✅ Success Rate:  %.1f%%\n", summary.SuccessRate()*100)
	}

	// ✅ Déclarer les variables en dehors des blocs if
	criticalCount := len(scan.GetCriticalFindings())
	highRiskCount := len(scan.GetHighRiskFindings()) - criticalCount // Remove critical from high
	mediumCount := len(scan.GetFindingsBySeverity(entities.SeverityMedium))
	lowCount := len(scan.GetFindingsBySeverity(entities.SeverityLow))
	infoCount := len(scan.GetFindingsBySeverity(entities.SeverityInfo))

	// Findings by severity
	if len(scan.GetAllFindings()) > 0 {
		fmt.Println("\n📋 Findings by Severity:")

		if criticalCount > 0 {
			fmt.Printf("  🚨 Critical: %d\n", criticalCount)
		}
		if highRiskCount > 0 {
			fmt.Printf("  ⚠️  High:     %d\n", highRiskCount)
		}
		if mediumCount > 0 {
			fmt.Printf("  🟡 Medium:   %d\n", mediumCount)
		}
		if lowCount > 0 {
			fmt.Printf("  🟢 Low:      %d\n", lowCount)
		}
		if infoCount > 0 {
			fmt.Printf("  ℹ️  Info:     %d\n", infoCount)
		}
	}

	// Module execution summary
	fmt.Println("\n🔧 Module Execution:")
	for _, execution := range scan.Executions() {
		status := "✅"
		if execution.IsFailed() {
			status = "❌"
		} else if execution.Status().String() == "skipped" {
			status = "⏭️"
		}

		fmt.Printf("  %s %s: %d findings (%s)\n",
			status,
			execution.Module().Name(),
			execution.FindingCount(),
			execution.Duration().Truncate(time.Millisecond))

		if execution.ErrorCount() > 0 {
			fmt.Printf("     Errors: %d\n", execution.ErrorCount())
		}
	}

	// ✅ Maintenant criticalCount et highRiskCount sont accessibles ici
	// Recommendations
	if criticalCount > 0 || highRiskCount > 0 {
		fmt.Println("\n🚨 Immediate Action Required:")
		fmt.Println("   Critical and high-risk findings detected!")
		fmt.Println("   Review the detailed report for remediation steps.")
	} else if len(scan.GetAllFindings()) == 0 {
		fmt.Println("\n🎉 Excellent! No security issues detected.")
	} else {
		fmt.Println("\n✅ Good overall security posture.")
		fmt.Println("   Consider addressing the identified issues for better security.")
	}

	fmt.Println(strings.Repeat("=", 60))
}
