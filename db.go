package authr

import (
    "context"
    "errors"
    "fmt"
    "github.com/davecgh/go-spew/spew"
    "github.com/twinj/uuid"
    _ "gorm.io/driver/mysql"
    _ "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

//-------------DATABASE FUNCTIONS---------------------

func (s *service) LoadUser(c context.Context, ID string) (*User, error) {
    if ID == "" {
        return nil, errors.New("ID is invalid")
    }

    users := make([]User, 0)
    // Get all records
    _ = s.db.Find(&users)
    // SELECT * FROM users;

    //fmt.Printf("users: %d\n", len(users))
    spew.Dump(users)
    var authUser User
    //fmt.Printf("1\n")
    dbRresult := s.db.Limit(1).Where("ID =   ?", ID).Find(&authUser)
    //fmt.Printf("2\n")
    if errors.Is(dbRresult.Error, gorm.ErrRecordNotFound) {
        return nil, errors.New("ID not found")
    }
    //fmt.Printf("3\n")
    if authUser.Username == "" {
        //fmt.Printf("4a\n")
        return nil, errors.New("record empty")
    }

    //fmt.Printf("6\n------------------------------------\n")
    //spew.Dump(authUser)
    return &authUser, nil
}

func (s *service) LoginUser(c context.Context, loginParams *LoginParams) (*User, error) {
    if loginParams.Username == "" || loginParams.Password == "" {
        return nil, errors.New("login params are invalid")
    }

    users := make([]User, 0)
    // Get all records
    _ = s.db.Find(&users)
    // SELECT * FROM users;

    //fmt.Printf("users: %d\n", len(users))
    spew.Dump(users)
    var authUser User
    //fmt.Printf("1\n")
    dbRresult := s.db.Limit(1).Where("Username =   ?", loginParams.Username).Find(&authUser)
    //fmt.Printf("2\n")
    if errors.Is(dbRresult.Error, gorm.ErrRecordNotFound) {
        return nil, errors.New("username or Password is incorrect - nf")
    }
    //fmt.Printf("3\n")
    if authUser.Username == "" {
        //fmt.Printf("4a\n")
        return nil, errors.New("username or Password is incorrect")
    }

    //fmt.Printf("4b\n")
    //fmt.Printf("4b\n")
    check := CheckPasswordHash(loginParams.Password, authUser.Password)
    //fmt.Printf("5\n")
    if !check {
        fmt.Printf("5a\n")
        return nil, errors.New("username or password is incorrect")
    }

    //fmt.Printf("6\n------------------------------------\n")
    //spew.Dump(authUser)
    return &authUser, nil
}

func (s *service) RegisterUser(c context.Context, regParams *RegistrationParams) (*User, error) {
    if regParams.Username == "" || regParams.Password == "" {
        return nil, errors.New("registration params are invalid")
    }

    fmt.Printf("E0.1\n")
    fmt.Printf("E0.3\n")
    var dbuser User
    s.db.Where("username = ?", regParams.Username).First(&dbuser)
    fmt.Printf("E0.4\n")
    //check email is already registered or not
    if dbuser.Username != "" {
        fmt.Printf("E1\n")
        return nil, errors.New("username already in use")
    }

    var err error
    user := User{Username: regParams.Username, Email: regParams.Email, ID: uuid.NewV4().String()}
    user.Password, err = GeneratePasswordHash(regParams.Password)
    if err != nil {
        fmt.Printf("E2\n")
        return nil, err
    }

    user.Roles = "ROLE_ADMIN,ROLE_MODERATOR"
    fmt.Printf("E3\n")
    //insert user details in database
    s.db.Create(&user)
    return &user, nil
}

// InitialMigration create user table in userdb
func (s *service) InitialMigration() error {
    s.db.AutoMigrate(User{}, AuthTokens{})
    return nil
}
