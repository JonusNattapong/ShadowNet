package db

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"github.com/stretchr/testify/suite"
)

type DBSuite struct {
	suite.Suite
	DB *sql.DB
}

func (s *DBSuite) SetupSuite() {
	// Override config for testing
	os.Setenv("SHADOWNET_ENV", "test")
	
	// Initialize test database
	err := InitTestDB()
	s.Require().NoError(err, "Failed to initialize test database")
	s.DB = GetTestDB()
}

func (s *DBSuite) TearDownSuite() {
	if s.DB != nil {
		s.DB.Close()
	}
}

func (s *DBSuite) SetupTest() {
	// Clear database before each test
	_, err := s.DB.Exec("DELETE FROM attacks")
	s.Require().NoError(err, "Failed to clear attacks table")
	
	_, err = s.DB.Exec("DELETE FROM sessions") 
	s.Require().NoError(err, "Failed to clear sessions table")
}

func TestDBSuite(t *testing.T) {
	suite.Run(t, new(DBSuite))
}
