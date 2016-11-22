package main

import (
	"fmt"
	"os"

	"github.com/iamdh4/goauth"
)

func main() {
	// Create the db object.
	db := new(goauth.Database)

	// Load the database. [file location], [salt]
	// You can use a string of any length for the salt.
	err := db.LoadDatabase("users.db", "h&$!z4@d8XN8xWIF")
	if err != nil {
		// Failed to load the database
		fmt.Println("Failed to load database. Error:", err.Error())
		os.Exit(1)
	}

	// Adding a user is as simple as passing
	// [username] & [password] to AddUser().
	db.AddUser("user1", "password")

	// Will fail because user already exists
	err = db.AddUser("user1", "password")
	if err != nil {
		// Failed to load the database
		fmt.Println("Failed to add user. Error:", err.Error())
	}

	db.AddUser("user2", "diffpass")

	// Get a list of usernames from the database.
	users := db.GetUserList()
	fmt.Println(users)

	// Check if a user exists in the database.
	// Will return a boolen
	user := "user1"
	if db.UserExists(user) {
		fmt.Println(user, "is in the database")
	} else {
		fmt.Println(user, "is not in the database")
	}

	user = "nonexistant"
	if db.UserExists(user) {
		fmt.Println(user, "is not in the database")
	} else {
		fmt.Println(user, "is not in the database")
	}

	// Authenticate a user. Will return a boolen
	user = "user1"
	pass := "password"
	if db.Authenticate(user, pass) {
		fmt.Println(user, "passed authentication.")
	} else {
		fmt.Println(user, "failed authentication.")
	}

	// Update user in the database
	err = db.UpdateUser("user2", "anewpass")
	if err != nil {
		// Failed remove user.
		fmt.Println("Failed to update user. Error:", err.Error())
	}

	// Remove a user from the database
	err = db.RemoveUser("user2")
	if err != nil {
		// Failed remove user.
		fmt.Println("Failed to add user. Error:", err.Error())
	} else {
		fmt.Println("Removed \"user2\"")
		fmt.Println(db.GetUserList())
	}

}
