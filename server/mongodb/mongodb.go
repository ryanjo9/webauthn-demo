package mongodb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/fxamacker/webauthn"
	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct {
	Client *mongo.Client
}

type RawPasskey struct {
	CredentialID  string `bson:"credentialId"`
	Counter       uint32 `bson:"counter"`
	RawCredential string `bson:"credential"`
}

type User struct {
	Username   string     `bson:"username"`
	RawPasskey RawPasskey `bson:"passkey"`
}

type Options struct {
	Challenge string `bson:"challenge"`
	Options   string `bson:"optionString"`
}

func New() MongoDB {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	uri := os.Getenv("MONGO_URI")
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	return MongoDB{
		Client: client,
	}
}

func (m *MongoDB) GetUserById(id string) (*User, error) {
	coll := m.Client.Database("webauthn-demo").Collection("users")
	var user *User

	objId, err := primitive.ObjectIDFromHex(id)
	err = coll.FindOne(context.TODO(), bson.D{{"_id", objId}}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		fmt.Printf("No document was found with the id %s\n", id)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (m *MongoDB) CreateUser(user *User) (string, error) {
	coll := m.Client.Database("webauthn-demo").Collection("users")

	resp, err := coll.InsertOne(context.TODO(), user)
	if err != nil {
		return "", err
	}
	id, _ := resp.InsertedID.(primitive.ObjectID)
	return id.Hex(), nil
}

func (m *MongoDB) UpdateUser(userID string, user *User) error {
	coll := m.Client.Database("webauthn-demo").Collection("users")

	update := bson.M{
		"$set": bson.M{
			"passkey": bson.M{
				"credentialId": user.RawPasskey.CredentialID,
				"counter":      user.RawPasskey.Counter,
				"credential":   user.RawPasskey.RawCredential,
			},
		},
	}

	objId, err := primitive.ObjectIDFromHex(userID)

	_, err = coll.UpdateByID(context.TODO(), objId, update)
	fmt.Println(err)
	return err
}

func (m *MongoDB) SavePasskey(userID string, authndata *webauthn.AuthenticatorData) error {
	coll := m.Client.Database("webauthn-demo").Collection("users")

	objId, _ := primitive.ObjectIDFromHex(userID)

	update := bson.M{
		"$set": bson.M{
			"passkey": bson.M{
				"credentialId": base64.RawURLEncoding.EncodeToString(authndata.CredentialID),
				"counter":      authndata.Counter,
				"credential":   base64.RawURLEncoding.EncodeToString(authndata.Credential.Raw),
			},
		},
	}
	_, err := coll.UpdateByID(context.TODO(), objId, update)
	return err
}

func (m *MongoDB) SaveRegistrationOptions(opts *webauthn.PublicKeyCredentialCreationOptions) error {
	coll := m.Client.Database("webauthn-demo").Collection("options")
	optsJSON, _ := json.Marshal(opts)

	val := bson.M{
		"challenge":    base64.RawURLEncoding.EncodeToString(opts.Challenge),
		"optionString": base64.RawURLEncoding.EncodeToString(optsJSON),
	}
	_, err := coll.InsertOne(context.TODO(), val)
	return err
}

func (m *MongoDB) GetRegistrationOptions(challenge string) (*webauthn.PublicKeyCredentialCreationOptions, error) {
	coll := m.Client.Database("webauthn-demo").Collection("options")

	val := bson.M{
		"challenge": challenge,
	}
	var opts Options
	err := coll.FindOne(context.TODO(), val).Decode(&opts)
	if err == mongo.ErrNoDocuments {
		fmt.Printf("No document was found with the challenge %s\n", challenge)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	optsJSON, _ := base64.RawURLEncoding.DecodeString(opts.Options)

	var returnOpts *webauthn.PublicKeyCredentialCreationOptions
	json.Unmarshal(optsJSON, &returnOpts)

	return returnOpts, nil
}

func (m *MongoDB) SaveAuthenticationOptions(opts *webauthn.PublicKeyCredentialRequestOptions) error {
	coll := m.Client.Database("webauthn-demo").Collection("options")
	optsJSON, _ := json.Marshal(opts)

	val := bson.M{
		"challenge":    base64.RawURLEncoding.EncodeToString(opts.Challenge),
		"optionString": base64.RawURLEncoding.EncodeToString(optsJSON),
	}
	_, err := coll.InsertOne(context.TODO(), val)
	return err
}

func (m *MongoDB) GetAuthenticationOptions(challenge string) (*webauthn.PublicKeyCredentialRequestOptions, error) {
	coll := m.Client.Database("webauthn-demo").Collection("options")

	val := bson.M{
		"challenge": challenge,
	}
	var opts Options
	err := coll.FindOne(context.TODO(), val).Decode(&opts)
	if err == mongo.ErrNoDocuments {
		fmt.Printf("No document was found with the challenge %s\n", challenge)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	optsJSON, _ := base64.RawURLEncoding.DecodeString(opts.Challenge)

	var returnOpts *webauthn.PublicKeyCredentialRequestOptions
	json.Unmarshal(optsJSON, &returnOpts)

	return returnOpts, nil
}

func (m *MongoDB) DeleteOptions(challenge string) error {
	coll := m.Client.Database("webauthn-demo").Collection("options")

	val := bson.M{
		"challenge": challenge,
	}
	_, err := coll.DeleteOne(context.TODO(), val)
	return err
}
