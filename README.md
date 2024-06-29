# JWE Token Demonstration Project

This project demonstrates the use of JSON Web Encryption (JWE) in a Spring Boot application. It includes two simple GET APIs and basic JWE token handling.

## Table of Contents

- [Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Installing](#installing)
- [Running the Application](#running-the-application)
- [Accessing the APIs](#accessing-the-apis)
- [Security](#security)
- [Example Usage](#example-usage)


## Getting Started

These instructions will help you set up and run the project on your local machine.

## Prerequisites

- Java 8 or higher
- Maven

## Installing

Clone the repository to your local machine:

```sh
git clone https://github.com/Yash-Gaglani/jwe-token-authentication.git
cd jwe-token-authentication
```

## Running the Application

Build and run the application using Maven:

```sh
mvn clean install
mvn spring-boot:run
```

The application will start on port 5000.

## Accessing the APIs

### /token

This endpoint returns a JWE token.

Example request:

```sh
curl -X GET http://localhost:5000/token -H "Content-Type: application/json"
```

Response:

```json
{
    "token": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..V05rh0rr7MJ7iw5L.U2f4Tcm6yZG1H5g.TgXGKbJ5sdQ"
}
```

### /

This endpoint returns a simple "Hello World" message, accessible only with a valid JWE token.

Example request:

```sh
curl -X GET http://localhost:5000/ -H "Authorization: Bearer <your-jwe-token>"
```

Response:

```json
{
    "message": "Hello World"
}
```

## Security

This project uses JWE tokens to secure endpoints. The token is checked only for its expiry. You can add additional verification parameters and logic in the `JWTAuthenticationFilter` class. The key used for token encryption can be configured in the `JWTTokenHelper` class.

## Example Usage

1. **Generate a JWE token:**

```sh
curl -X GET http://localhost:5000/token -H "Content-Type: application/json"
```

2. **Access the protected resource with the token:**

```sh
curl -X GET http://localhost:5000/ -H "Authorization: Bearer eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..V05rh0rr7MJ7iw5L.U2f4Tcm6yZG1H5g.TgXGKbJ5sdQ"
```

Feel free to customize the content in each section as needed for your project.
