package fr.nrich.utils;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.nrich.model.auth.dto.JwtAuthenticationResponse;

public class TestUtils {

    // Auth end points
    public static final String AUTH_END_POINT = "/auth";
    public static final String AUTHENTICATION_URL = AUTH_END_POINT + "/authenticate";
    public static final String REGISTER_URL = AUTH_END_POINT + "/register";
    public static final String REFRESH_URL = AUTH_END_POINT + "/token";

    //
    public static final String SIMPLE_ENTRY_POINT = "/hello";

    // Usernames and passwords for tests
    public static final String ADMIN_USERNAME = "admin";
    public static final String ADMIN_PASSWORD = "password";
    public static final String SIMPLE_USER_USERNAME = "user";
    public static final String SIMPLE_USER_PASSWORD = "password";
    public static final String WRONG_PASSWORD = "wrongPassword";
    public static final String WRONG_USERNAME = "wrongUsername";

    static ObjectMapper objectMapper = new ObjectMapper();

    public static String createJsonString(String... strings) throws IllegalArgumentException {
        if (strings.length % 2 != 0)
            throw new IllegalArgumentException("Should have even number of parameter");

        List<String> jsonData = new ArrayList<>();
        for (int i = 0; i < strings.length; i += 2) {
            jsonData.add("\"" + strings[i] + "\":\"" + strings[i + 1] + "\"");
        }

        return "{" + String.join(",", jsonData) + "}";
    }

    public static String getValueFromJson(String field, String json) {
        Pattern pattern = Pattern.compile("\"" + field + "\":\"(.*?)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        throw new RuntimeException("Could not find field " + field + " in json " + json);
    }

    public static Map<String, String> getJsonAsMap(String json) throws Exception {
        TypeReference<HashMap<String, String>> typeRef = new TypeReference<HashMap<String, String>>() {
        };
        return objectMapper.readValue(json, typeRef);
    }

    public static JwtAuthenticationResponse authenticateAdmin(MockMvc mockMvc) throws Exception {
        return authenticate(ADMIN_USERNAME, ADMIN_PASSWORD, mockMvc);
    }

    public static JwtAuthenticationResponse authenticateUser(MockMvc mockMvc) throws Exception {
        return authenticate(SIMPLE_USER_USERNAME, SIMPLE_USER_PASSWORD, mockMvc);
    }

    public static JwtAuthenticationResponse authenticate(String username, String password, MockMvc mockMvc)
            throws Exception {
        String authForm = createJsonString("username", username, "password", password);

        String result = mockMvc.perform(post(AUTHENTICATION_URL).contentType(MediaType.APPLICATION_JSON).content(authForm))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        return objectMapper.readValue(result, JwtAuthenticationResponse.class);
    }

    public static HttpHeaders adminAuthorizationHeader(MockMvc mockMvc) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(authenticateAdmin(mockMvc).getToken());
        return headers;
    }

    public static HttpHeaders userAuthorizationHeader(MockMvc mockMvc) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(authenticateAdmin(mockMvc).getToken());
        return headers;
    }

    public static String adminRefreshToken(MockMvc mockMvc) throws Exception {
        return authenticateAdmin(mockMvc).getRefreshToken();
    }
}
