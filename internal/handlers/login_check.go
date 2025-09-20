package handlers

import (
	"context"
	"database/sql"

	"secureshift/internal/mode"

	"golang.org/x/crypto/bcrypt"
)

// Kullanıcı şifresi eşleşiyor mu?
// Secure mod: SADECE bcrypt doğrulaması (hash'i yazmak işe yaramaz).
// Insecure mod: düz-metin eşitliği.
func VerifyUserPassword(ctx context.Context, username, supplied string) (bool, error) {
	var stored string
	err := DB.QueryRowContext(ctx, "SELECT COALESCE(password,'') FROM users WHERE username=?", username).
		Scan(&stored)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	if mode.IsSecure() {
		// ✅ Secure mod: sadece bcrypt
		if bcrypt.CompareHashAndPassword([]byte(stored), []byte(supplied)) == nil {
			return true, nil
		}
		return false, nil
	}

	// ❌ Insecure mod: düz-metin karşılaştırma
	return stored == supplied, nil
}
