package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/riadh-benchouche/security-audit-tool/pkg/api"
	"github.com/riadh-benchouche/security-audit-tool/pkg/core"
	"github.com/riadh-benchouche/security-audit-tool/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	target  string
	modules []string
	output  string
	verbose bool
)

// rootCmd représente la commande de base quand appelée sans sous-commandes
var rootCmd = &cobra.Command{
	Use:   "security-audit",
	Short: "Un outil d'audit de sécurité moderne et extensible",
	Long:  `Security Audit Tool est un scanner de sécurité open source qui permet d'automatiser les tâches d'audit répétitives.`,
	Run:   runScan,
}

// scanCmd représente la commande scan
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Lance un scan de sécurité",
	Long:  `Lance un scan de sécurité sur la cible spécifiée avec les modules sélectionnés.`,
	Run:   runScan,
}

// serverCmd représente la commande server
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Lance le serveur web pour l'interface graphique",
	Long:  `Lance le serveur web pour accéder à l'interface graphique du scanner.`,
	Run:   runServer,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Flags globaux
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "fichier de configuration (défaut: $HOME/.security-audit.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "sortie détaillée")

	// Flags pour scan
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "cible à scanner (IP, domaine, ou CIDR)")
	scanCmd.Flags().StringSliceVarP(&modules, "modules", "m", []string{"network"}, "modules à utiliser (network,http,ssl)")
	scanCmd.Flags().StringVarP(&output, "output", "o", "", "fichier de sortie (JSON)")

	// Marquer les flags requis
	scanCmd.MarkFlagRequired("target")

	// Ajouter les sous-commandes
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(serverCmd)
}

func initConfig() {
	config := core.NewConfig()
	if cfgFile != "" {
		config.SetConfigFile(cfgFile)
		if err := config.Load(); err != nil {
			fmt.Printf("Erreur lors du chargement de la configuration: %v\n", err)
			fmt.Println("Utilisation de la configuration par défaut...")
		}
	}
	// Si pas de fichier de config, utiliser les valeurs par défaut uniquement

	// Initialiser le logger
	logger := core.NewLogger(verbose)
	logger.Info("Security Audit Tool démarré")
}

func runScan(cmd *cobra.Command, args []string) {
	logger := core.GetLogger()
	logger.Infof("Démarrage du scan pour la cible: %s", target)
	logger.Infof("Modules sélectionnés: %v", modules)

	// Créer le scanner manager
	scanManager := scanner.NewManager()

	// Configurer les modules à utiliser
	for _, module := range modules {
		switch module {
		case "network":
			scanManager.AddScanner(scanner.NewNetworkScanner())
		case "http":
			scanManager.AddScanner(scanner.NewHTTPScanner())
		default:
			logger.Warnf("Module inconnu: %s", module)
		}
	}

	// Lancer le scan
	results, err := scanManager.Scan(target)
	if err != nil {
		logger.Errorf("Erreur lors du scan: %v", err)
		os.Exit(1)
	}

	// Gérer la sortie
	outputHandler := core.NewOutput()
	if output != "" {
		// Si le chemin ne commence pas par results/ et n'est pas absolu, l'ajouter
		if !strings.HasPrefix(output, "results/") && !strings.HasPrefix(output, "/") && !strings.Contains(output, ":") {
			output = "results/" + output
		}

		err = outputHandler.SaveToFile(results, output)
		if err != nil {
			logger.Errorf("Erreur lors de la sauvegarde: %v", err)
			os.Exit(1)
		}
		logger.Infof("Résultats sauvegardés dans: %s", output)
	} else {
		outputHandler.PrintToConsole(results)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	logger := core.GetLogger()
	logger.Info("Démarrage du serveur web...")

	server := api.NewServer()
	if err := server.Start(":8080"); err != nil {
		logger.Errorf("Erreur lors du démarrage du serveur: %v", err)
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
