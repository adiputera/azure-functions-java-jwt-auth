# Azure Functions Node.js JWT Auth
This project is an Azure Functions application that implements JWT (JSON Web Token) authentication, built with Node.js.

## Dependencies
- [azure-functions-java-library](https://github.com/Azure/azure-functions-java-library)
- [auth0 Java-JWT](https://github.com/auth0/java-jwt)

## Requirements
- JDK > 21

## Getting Started

### Installation
1. Clone the repository
2. Navigate to the project directory
3. Install the dependencies and compile the project:
    ```bash
    mvn clean install
    ```

### Configuration
- All the client ID & client secret are stored in environment variables. For local testing, check [local.settings.json](local.settings.json).
  To add new client ID, just add new entries in the environment variables, the key would be the client ID, and the value would be client secret.
- JWT secret key is stored in environment variables as `jwt_secret_key`
- JWT expired time is stored in environment variables as `jwt_expire_time`

### Running the Application
To start the application, execute:
```
mvn azure-functions:run
```

## Usage
- **Authentication Endpoint**: [POST] `/api/auth?client_id=${cliendID}&client_secret=${clientSecret}`
    ```bash
    curl --location --request POST 'http://localhost:7071/api/auth?client_id=test_client&client_secret=XX0VmfQAk0awWwoBEQSi'
    ```
  the response for correct client ID and client secret:
    ```json
    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZGlwdXRlcmEiLCJzdWIiOiJ0ZXN0X2NsaWVudCIsImlhdCI6MTc0MDU1NDE0OCwiZXhwIjoxNzQwNTU1MDQ4fQ.vG6AjzZw96LmP81XwQUDy_h5Z1qwQypDzH-IsSuddLs",
        "token_type": "Bearer",
        "expiresIn": 890
    }
    ```
  the response if either client ID or client secret is wrong or missing:
    ```json
    {
        "error": "Invalid credential"
    }
    ```
- **Protected Endpoint**: [POST] `/api/endpoint`
    ```bash
    curl --location --request POST 'http://localhost:7071/api/endpoint' \
    --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZGlwdXRlcmEiLCJzdWIiOiJ0ZXN0X2NsaWVudCIsImlhdCI6MTc0MDU1NDE0OCwiZXhwIjoxNzQwNTU1MDQ4fQ.vG6AjzZw96LmP81XwQUDy_h5Z1qwQypDzH-IsSuddLs'
    ```
  the response if authenticated successfully:
    ```json
    {
        "message": "You have access to this endpoint"
    }
    ```
  the response if failed authenticated:
    ```json
    {
        "error": "Unauthorized"
    }
    ```

## Contributing
Contributions are welcome! Please submit a pull request or open an issue to discuss any changes.
