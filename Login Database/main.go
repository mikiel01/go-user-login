package main

import (
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
)

const salt_half_length = 6

func GenerateSalt(n int) string {

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	salt := fmt.Sprintf("%X", b)
	return salt
}

func initDb() *sql.DB {

	db_host_value := ReadTextFile("dbhost.txt")
	db_port_value := ReadTextFile("dbport.txt")
	db_user_value := ReadTextFile("dbuser.txt")
	db_pass_value := ReadTextFile("dbpass.txt")
	db_name_value := ReadTextFile("dbname.txt")

	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+"password=%s dbname=%s sslmode=disable",
		db_host_value, db_port_value, db_user_value, db_pass_value, db_name_value)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Succesfully connected")
	if _, err = db.Query("CREATE TABLE IF NOT EXISTS Users (user_id SERIAL PRIMARY KEY,	username VARCHAR(64) UNIQUE,	password VARCHAR(128), salt VARCHAR(32)	)"); err != nil {
		fmt.Println(http.StatusInternalServerError)
		fmt.Println(err)
		return nil
	}
	fmt.Println("Success")
	return db
}

var db = initDb()

type User struct {
	Username string
	Password string
	Salt     string
	User_id  uint64
}

func ReadTextFile(filename string) string {
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	return strings.TrimRight(string(body), "\r\n")
}

func HashString(s string) string {
	h := sha512.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(user)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	salt := GenerateSalt(salt_half_length)
	pepper := ReadTextFile("pepper.txt")
	stringToHash := salt + user.Password + pepper
	hash := HashString(stringToHash)

	if _, err = db.Query("INSERT INTO Users (Username, Password, Salt) VALUES ($1, $2, $3)", user.Username, hash, salt); err != nil {
		fmt.Println(http.StatusInternalServerError)
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Println("Success")
}

func Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Logged In")
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sqlStatement := "SELECT user_id, password, salt FROM Users WHERE Username=$1"
	// var id int
	result := db.QueryRow(sqlStatement, user.Username)
	tempUser := &User{}
	switch err := result.Scan(&tempUser.User_id, &tempUser.Password, &tempUser.Salt); err {
	case sql.ErrNoRows:
		fmt.Println("No rows were returned!")
	case nil:
		fmt.Println("Retrieved row")
	default:
		panic(err)
	}

	pepper := ReadTextFile("pepper.txt")
	fmt.Println(tempUser.Password)
	stringToHash := tempUser.Salt + user.Password + pepper

	if HashString(stringToHash) != tempUser.Password {
		fmt.Println("Error: Invalid Username or Password")
		return
	}
	token, err := CreateToken(tempUser.User_id)
	expiration := time.Now().Add(15 * time.Minute)
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: expiration,
	})
	fmt.Println("Login Successful")
}

func CreateToken(userid uint64) (string, error) {
	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", ReadTextFile("secret.txt"))
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["user_id"] = userid
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := access.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}

func Logout(w http.ResponseWriter, r *http.Request) {
	c := http.Cookie{
		Name:   "token",
		MaxAge: -1}
	http.SetCookie(w, &c)

	w.Write([]byte("Logged out!\n"))
}

func main() {
	http.HandleFunc("/login", Login)
	http.HandleFunc("/signup", CreateUser)
	http.HandleFunc("/logout", Logout)
	log.Fatal(http.ListenAndServe(":8000", nil))
}
