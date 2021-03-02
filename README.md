# Authenticated API Starter Project

## Description

This project contains all I need to start a new project with a RESTful API authenticated with JWT tokens

## 

## Authentication

### Production

Set Environment variable **APPLICATION_SECRET** with a secret.

You can generate a secret in a terminal using node :

```
$ node
> require('crypto').randomBytes(64).toString('hex')
```

Most of the authentication code comes from here : https://www.javainuse.com/spring/boot-jwt-mysql

## Tests

Using `MockMvc` for tests, here is an example :

```java
@Test
public void shouldAllowAccessUsingToken() throws Exception {
    // Act, assert
    this.mockMvc.perform(get(SIMPLE_ENTRY_POINT).headers(adminAuthorizationHeader(mockMvc)))
        .andExpect(status().isOk());
}
```

See: https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/test/web/servlet/MockMvc.html