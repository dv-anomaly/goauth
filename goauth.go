package goauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
)

//Database Database Object
type Database struct {
	Location string
	Salt     string
	Cache    UsersObject
}

//UsersObject User Object
type UsersObject struct {
	Users []UsersType
}

//UsersType User Type
type UsersType struct { //test
	Username string
	Password string
}

//DoError Struct for errors.
type DoError struct {
	eType   string
	eString string
}

func (e *DoError) Error() string {
	return e.eString
}

func (db *Database) hash(pass string) string {
	hasher := sha256.New()
	io.WriteString(hasher, string(pass)+db.Salt)
	salthash := hex.EncodeToString(hasher.Sum(nil))
	io.WriteString(hasher, string(pass)+salthash)
	passhash := hex.EncodeToString(hasher.Sum(nil))
	return passhash
}

func (db *Database) encrypt(text []byte) ([]byte, error) {
	hasher := sha1.New()
	io.WriteString(hasher, db.Salt)
	hash := hex.EncodeToString(hasher.Sum(nil))[:16]
	block, err := aes.NewCipher([]byte(hash))
	if err != nil {
		return text, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return text, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return ciphertext, nil
}

func (db *Database) decrypt(cryptoText []byte) ([]byte, error) {
	hasher := sha1.New()
	io.WriteString(hasher, db.Salt)
	hash := hex.EncodeToString(hasher.Sum(nil))[:16]
	block, err := aes.NewCipher([]byte(hash))
	if err != nil {
		return cryptoText, err
	}
	iv := cryptoText[:aes.BlockSize]
	cryptoText = cryptoText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cryptoText, cryptoText)
	return cryptoText, err
}

func (db *Database) readDatabase() (UsersObject, DoError) {
	var content UsersObject
	var err DoError
	file, e := ioutil.ReadFile(db.Location)
	if e != nil {
		err = DoError{"nofile", "Could not open database file."}
	} else {
		rawdata, e := db.decrypt(file)
		if e != nil {
			return db.Cache, DoError{"decrypt", "Filed to Decrypt database."}
		}
		e = json.Unmarshal(rawdata, &content)
		if e != nil {
			err = DoError{"corrupt", "Database is corrupted or invalid."}
		} else {
			err = DoError{"", ""}
		}
	}
	return content, err
}

func (db *Database) writeDatabase() error {
	data, _ := json.Marshal(db.Cache)
	encdata, e := db.encrypt(data)
	if e != nil {
		return e
	}
	err := ioutil.WriteFile(db.Location, encdata, 0644)
	return err
}

//LoadDatabase Initialize the database Object.
func (db *Database) LoadDatabase(location string, salt string) error {
	db.Location = location
	db.Salt = salt
	var e DoError
	var err error
	db.Cache, e = db.readDatabase()
	if e.eType == "nofile" {
		e = DoError{"", ""}
		db.writeDatabase()
	}
	if e.eType == "" {
		err = nil
	} else {
		err = &e
	}
	return err
}

//UserExists Check if user exists in database. Returns boolen
func (db *Database) UserExists(username string) bool {
	status := false
	for _, user := range db.Cache.Users {
		if username == user.Username {
			status = true
			break
		}
	}
	return status
}

//AddUser Add new user to database.
func (db *Database) AddUser(username string, password string) error {
	if db.UserExists(username) {
		return &DoError{"exists", "User already in database."}
	}
	db.Cache.Users = append(db.Cache.Users, UsersType{username, db.hash(password)})
	err := db.writeDatabase()
	if err != nil {
		db.RemoveUser(username)
		return err
	}
	return nil
}

//RemoveUser Remove user from database.
func (db *Database) RemoveUser(username string) error {
	for i, user := range db.Cache.Users {
		if user.Username == username {
			var result []UsersType
			result = append(result, db.Cache.Users[0:i]...)
			result = append(result, db.Cache.Users[i+1:]...)
			db.Cache.Users = result
			err := db.writeDatabase()
			return err
		}
	}
	return &DoError{"notfound", "User not in database."}
}

//UpdateUser Update existing user in database.
func (db *Database) UpdateUser(username string, password string) error {
	for i, user := range db.Cache.Users {
		if user.Username == username {
			db.Cache.Users[i].Password = db.hash(password)
			return db.writeDatabase()
		}
	}
	return &DoError{"notfound", "User not in database."}
}

//GetUserList Returns a list of users from the database.
func (db *Database) GetUserList() []string {
	var users []string
	for _, user := range db.Cache.Users {
		users = append(users, user.Username)
	}
	return users
}

//Authenticate Authenticate users against database. Returns boolen
func (db *Database) Authenticate(username string, password string) bool {
	for _, user := range db.Cache.Users {
		if user.Username == username {
			if db.hash(password) == user.Password {
				return true
			}
		}
	}
	return false
}
