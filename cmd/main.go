package main

import (
	"shadownet/ai"
	"shadownet/analyzer"
	"shadownet/db"
	"shadownet/honeypot"
	"shadownet/utils"
)

func main() {
    utils.InitLogger()
    db.Connect()

    // Start honeypots
    go honeypot.StartSSHServer(2222)
    go honeypot.StartHTTPServer(8080)
    go honeypot.StartFTPServer(2121)
    go honeypot.StartRDPServer(3389)
    go honeypot.StartSMPServer(445)
    go honeypot.StartModbusServer(502)
    go honeypot.StartMQTTServer(1883)

    // Start analyzer
    analyzer := analyzer.NewAnalyzer()
    go analyzer.Start()

    // Start RL agent
    aiAgent := ai.NewRLAgent()
    aiAgent.Train("attack_data.csv") // Train on historical attack data

    utils.Log.Info("ShadowNet initialized. Waiting for attackers...")
    select {}
}