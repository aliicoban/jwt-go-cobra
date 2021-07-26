package jwtgocobra

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"os"
	"strings"
	"time"
)

/*
Create token by user id.If operation is success return token.Otherwise return error.
*/
func CreateToken(userid interface{}, expireTime ...time.Duration) (string, error) {
	var setTimeOut time.Duration = 0
	var err error

	if len(expireTime) == 0 {
		fmt.Println("No value was sent therefore set to default value : 30ns")
		setTimeOut = (time.Minute) * 30
	} else if len(expireTime) > 0 && expireTime[0] < 0 {
		fmt.Println("Sent negative value therefore set to default value : 30ns")
		setTimeOut = (time.Minute) * 30
	} else {
		var timeOut = expireTime[0]
		setTimeOut = time.Minute * timeOut
		fmt.Printf("Set to : %v minutes \n", timeOut)
	}
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = time.Now().Add(setTimeOut).Unix()
	fmt.Println("Exp is a :", atClaims["exp"])
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}

/*
Parameter is a gin.Context.
Extract string token.
*/
func ExtractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	fmt.Println("Ext Token is", bearerToken)
	strArr := strings.Split(bearerToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

/*
Parameter is string token.
Return *jwt.Token type.
*/
func VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//make sure that token method confirm to ""SigninMethodHMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signin method : %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

/*
 tokenString type is string.If token is invalid return false otherwise returns true.
*/
func TokenValid(tokenString string) (error, bool) {
	token, err := VerifyToken(tokenString)
	fmt.Println("Token is:", token)
	if err != nil {
		return err, false
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		fmt.Println("invalidToken")
		return err, false
	}
	fmt.Println("token is valid")
	return nil, true
}

/*
Send token and getting the user id.
*/
func GetUserIdByToken(token *jwt.Token) interface{} {
	claims, _ := token.Claims.(jwt.MapClaims)
	fmt.Println("USERID", claims["user_id"])
	return claims["user_id"]
}