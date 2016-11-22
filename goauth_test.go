package goauth

import (
	"io/ioutil"
	"os"
	"testing"
)

func init() {
	os.Remove("test.db")
}

func TestErrorReporting(t *testing.T) {
	var err error
	value := "test"
	err = &DoError{"", value}
	if err.Error() != value {
		t.Errorf("Error strings not being processed correctly.")
	}
}

func TestLoadDatabase(t *testing.T) {
	ioutil.WriteFile("bad.db", []byte("garalsdfjlaksjdflkjasdlfkjalskdjflaksjdflkjasdlfkjaslkdfjalskjdflaksjdflakjsdflkajsfbagedata"), 0644)
	bdb := new(Database)
	err := bdb.LoadDatabase("bad.db", "salt")
	if err == nil {
		t.Errorf("Failed to detect currupt database.")
	}
	db := new(Database)
	err = db.LoadDatabase("test.db", "salt")
	if err != nil {
		t.Errorf("Failed to load create new database. Error: %s", err.Error())
	}
	os.Remove("bad.db")
}

func TestAddUser(t *testing.T) {
	db := new(Database)
	err := db.LoadDatabase("test.db", "salt")
	if err != nil {
		t.Errorf("Cannot run test without a database. Error: %s", err.Error())
		return
	}
	err = db.AddUser("test1", "test1")
	if err != nil {
		t.Errorf("Failed to create new user in database. Error: %s", err.Error())
		return
	}
	err = db.AddUser("test1", "test1")
	if err == nil {
		t.Errorf("Added duplicate user in database.")
	}
	db.AddUser("test2", "test2")
}

func TestGetUserList(t *testing.T) {
	db := new(Database)
	err := db.LoadDatabase("test.db", "salt")
	if err != nil {
		t.Errorf("Cannot run test without a database. Error: %s", err.Error())
		return
	}
	list := db.GetUserList()
	if len(list) != 2 {
		t.Errorf("User list is not the correct length.")
	}
}

func TestUpdateUser(t *testing.T) {
	db := new(Database)
	err := db.LoadDatabase("test.db", "salt")
	if err != nil {
		t.Errorf("Cannot run test without a database. Error: %s", err.Error())
		return
	}
	err = db.UpdateUser("test2", "newpass")
	if err != nil {
		t.Errorf("Failed to update user. Error: %s", err.Error())
	}
	err = db.UpdateUser("fail", "fail")
	if err == nil {
		t.Errorf("Updated a non existing user.")
	}
}

func TestRemoveUser(t *testing.T) {
	db := new(Database)
	err := db.LoadDatabase("test.db", "salt")
	if err != nil {
		t.Errorf("Cannot run test without a database. Error: %s", err.Error())
		return
	}
	err = db.RemoveUser("test2")
	if err != nil {
		t.Errorf("Failed to remove user. Error: %s", err.Error())
	}
	err = db.RemoveUser("fail")
	if err == nil {
		t.Errorf("Removed a non existing user.")
	}
}

func TestAuthenticate(t *testing.T) {
	db := new(Database)
	err := db.LoadDatabase("test.db", "salt")
	if err != nil {
		t.Errorf("Cannot run test without a database. Error: %s", err.Error())
		return
	}
	if db.Authenticate("test1", "test1") == false {
		t.Errorf("Failed to authenticate user.")
	}
	if db.Authenticate("test1", "fail") {
		t.Errorf("Authenticated user with incorrect credentials.")
	}
	os.Remove("test.db")
}
