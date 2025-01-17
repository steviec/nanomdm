//go:build integration
// +build integration

package mysql

import (
	"context"
	"errors"
	"flag"
	"io/ioutil"
	"testing"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage/internal/test"

	_ "github.com/go-sql-driver/mysql"
)

var flDSN = flag.String("dsn", "", "DSN of test MySQL instance")

func loadAuthMsg() (*mdm.Authenticate, error) {
	b, err := ioutil.ReadFile("../../mdm/testdata/Authenticate.2.plist")
	if err != nil {
		return nil, err
	}
	r, err := mdm.DecodeCheckin(b)
	if err != nil {
		return nil, err
	}
	a, ok := r.(*mdm.Authenticate)
	if !ok {
		return nil, errors.New("not an Authenticate message")
	}
	return a, nil
}

func loadTokenMsg() (*mdm.TokenUpdate, error) {
	b, err := ioutil.ReadFile("../../mdm/testdata/TokenUpdate.2.plist")
	if err != nil {
		return nil, err
	}
	r, err := mdm.DecodeCheckin(b)
	if err != nil {
		return nil, err
	}
	a, ok := r.(*mdm.TokenUpdate)
	if !ok {
		return nil, errors.New("not a TokenUpdate message")
	}
	return a, nil
}

const deviceUDID = "66ADE930-5FDF-5EC4-8429-15640684C489"

func newMdmReq() *mdm.Request {
	return &mdm.Request{
		Context: context.Background(),
		EnrollID: &mdm.EnrollID{
			Type: mdm.Device,
			ID:   deviceUDID,
		},
	}
}

func enrollTestDevice(storage *MySQLStorage) error {
	authMsg, err := loadAuthMsg()
	if err != nil {
		return err
	}
	err = storage.StoreAuthenticate(newMdmReq(), authMsg)
	if err != nil {
		return err
	}
	tokenMsg, err := loadTokenMsg()
	if err != nil {
		return err
	}
	err = storage.StoreTokenUpdate(newMdmReq(), tokenMsg)
	if err != nil {
		return err
	}
	return nil
}

func TestQueue(t *testing.T) {
	if *flDSN == "" {
		t.Fatal("MySQL DSN flag not provided to test")
	}

	storage, err := New(WithDSN(*flDSN))
	if err != nil {
		t.Fatal(err)
	}

	err = enrollTestDevice(storage)
	if err != nil {
		t.Fatal(err)
	}

	test.TestQueue(t, deviceUDID, storage)
}
