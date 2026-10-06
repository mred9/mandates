package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/mred9/mandates/internal/store/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Harness {
		db, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return storetest.Harness{
			Profiles:    NewProfileStore(db),
			Credentials: NewCredentialStore(db),
			Exec: func(ctx context.Context, sql string) error {
				_, err := db.ExecContext(ctx, sql)
				return err
			},
		}
	})
}
