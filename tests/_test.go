// Try delete user after test
package tests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/ib407ov/protos/gen/go/sso"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Create a new SQLite connection for cleanup
	db, err := sql.Open("sqlite3", st.Cfg.StoragePath)
	require.NoError(t, err)
	defer db.Close()

	// Log the SQLite database path
	t.Logf("SQLite database path: %s", st.Cfg.StoragePath)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	// Add a debug log to verify the registration
	t.Logf("Registered user ID: %v", respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err, "Login request failed")

	// Add a debug log to verify the login response
	t.Logf("Login response token: %v", respLogin.GetToken())

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	loginTime := time.Now()

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err, "Token parsing failed")

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	// Add debug logs to verify claims
	t.Logf("Token claims: %v", claims)

	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	// Check if exp of token is in correct range, ttl get from st.Cfg.TokenTTL
	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)

	// Cleanup the user created in the test
	t.Logf("Deleting user with email: %s", email)
	result, err := db.Exec("DELETE FROM users WHERE email = ?", email)
	require.NoError(t, err, "Failed to clean up database")

	rowsAffected, err := result.RowsAffected()
	require.NoError(t, err, "Failed to get rows affected")
	assert.Equal(t, int64(1), rowsAffected, "User was not deleted from database")

	// Verify that the user has been deleted
	row := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email)
	var count int
	err = row.Scan(&count)
	require.NoError(t, err, "Failed to count users")
	assert.Zero(t, count, "User was not deleted from database")
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
