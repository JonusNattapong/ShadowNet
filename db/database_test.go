package db

import (
	"testing"
	"time"

	"shadownet/types"

	"github.com/stretchr/testify/assert"
)

func TestRecordAttack(t *testing.T) {
    // Initialize test database
    err := InitTestDB()
    assert.NoError(t, err)
    defer GetTestDB().Close()

    now := time.Now()
    // Create test attack
    testAttack := types.Attack{
        Timestamp: now,
        SourceIP:  "192.168.1.1",
        Type:      types.AttackTypeSSHBruteForce,
        Details:   "Multiple failed login attempts",
    }

    // Record attack
    id, err := RecordAttack(GetTestDB(), testAttack)
    assert.NoError(t, err)
    assert.Greater(t, id, int64(0))

    // Verify attack was recorded
    var recordedIP, recordedType, recordedDetails string
    var recordedTime time.Time
    err = GetTestDB().QueryRow(
        "SELECT ip_address, attack_type, details, timestamp FROM attacks WHERE id = ?",
        id,
    ).Scan(&recordedIP, &recordedType, &recordedDetails, &recordedTime)
    assert.NoError(t, err)

    assert.Equal(t, testAttack.SourceIP, recordedIP)
    assert.Equal(t, testAttack.Type, recordedType)
    assert.Equal(t, testAttack.Details, recordedDetails)
    assert.True(t, recordedTime.Equal(now))
}

func TestLogAttack(t *testing.T) {
    // Initialize test database
    err := InitTestDB()
    assert.NoError(t, err)
    defer GetTestDB().Close()

    // Log test attack
    err = LogAttack("192.168.1.2", types.AttackTypeSQLInjection, "SQL injection attempt detected")
    assert.NoError(t, err)

    // Verify attack was logged
    attack, err := GetLatestAttack()
    assert.NoError(t, err)
    assert.Equal(t, "192.168.1.2", attack.SourceIP)
    assert.Equal(t, types.AttackTypeSQLInjection, attack.Type)
    assert.Equal(t, "SQL injection attempt detected", attack.Details)
}

func TestGetLatestAttack(t *testing.T) {
    // Initialize test database
    err := InitTestDB()
    assert.NoError(t, err)
    defer GetTestDB().Close()

    // Record multiple attacks
    attacks := []types.Attack{
        {
            Timestamp: time.Now().Add(-2 * time.Hour),
            SourceIP:  "10.0.0.1",
            Type:      types.AttackTypeSSHBruteForce,
            Details:   "First attack",
        },
        {
            Timestamp: time.Now().Add(-1 * time.Hour),
            SourceIP:  "10.0.0.2",
            Type:      types.AttackTypeSQLInjection,
            Details:   "Second attack",
        },
    }

    for _, attack := range attacks {
        _, err := RecordAttack(GetTestDB(), attack)
        assert.NoError(t, err)
    }

    // Get latest attack
    latest, err := GetLatestAttack()
    assert.NoError(t, err)
    assert.Equal(t, "10.0.0.2", latest.SourceIP)
    assert.Equal(t, types.AttackTypeSQLInjection, latest.Type)
    assert.Equal(t, "Second attack", latest.Details)
}
