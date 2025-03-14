package ai

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"shadownet/utils"
)

// RLAgent represents the reinforcement learning agent
type RLAgent struct {
    modelPath string
    threatIntel interface{} // Will be set by SetThreatIntelligence
    countermeasures interface{} // Will be set by SetCountermeasures
}

// NewRLAgent creates a new reinforcement learning agent
func NewRLAgent() *RLAgent {
    return &RLAgent{
        modelPath: filepath.Join("ai", "attack_classifier.pkl"),
    }
}

// SetThreatIntelligence sets the threat intelligence interface
func (a *RLAgent) SetThreatIntelligence(ti interface{}) {
    a.threatIntel = ti
}

// SetCountermeasures sets the countermeasures interface
func (a *RLAgent) SetCountermeasures(cm interface{}) {
    a.countermeasures = cm
}

// Train trains the ML model using historical data
func (a *RLAgent) Train(dataPath string) error {
    utils.Log.Info("Starting ML model training...")
    
    cmd := exec.Command("python3", "ai/ml_trainer.py")
    if output, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("training failed: %v, output: %s", err, output)
    }

    utils.Log.Info("ML model training completed successfully")
    return nil
}

// Recommendation represents an AI recommendation for handling a threat
type Recommendation struct {
    Action  string // "block" or "counterattack"
    Exploit string // specific exploit to use if Action is "counterattack"
    Score   float64 // confidence score 0-1
}

// GetRecommendation analyzes a threat and returns a recommended action
func (a *RLAgent) GetRecommendation(threat interface{}) Recommendation {
    // For now, return a conservative default recommendation
    // In a real implementation, this would use the trained model
    return Recommendation{
        Action: "block",
        Score:  0.95,
    }
}