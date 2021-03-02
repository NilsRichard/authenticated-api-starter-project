package fr.nrich;

import static fr.nrich.utils.TestUtils.ADMIN_PASSWORD;
import static fr.nrich.utils.TestUtils.ADMIN_USERNAME;
import static fr.nrich.utils.TestUtils.AUTHENTICATION_URL;
import static fr.nrich.utils.TestUtils.REFRESH_URL;
import static fr.nrich.utils.TestUtils.REGISTER_URL;
import static fr.nrich.utils.TestUtils.SIMPLE_ENTRY_POINT;
import static fr.nrich.utils.TestUtils.SIMPLE_USER_PASSWORD;
import static fr.nrich.utils.TestUtils.SIMPLE_USER_USERNAME;
import static fr.nrich.utils.TestUtils.WRONG_PASSWORD;
import static fr.nrich.utils.TestUtils.WRONG_USERNAME;
import static fr.nrich.utils.TestUtils.adminAuthorizationHeader;
import static fr.nrich.utils.TestUtils.adminRefreshToken;
import static fr.nrich.utils.TestUtils.authenticateAdmin;
import static fr.nrich.utils.TestUtils.createJsonString;
import static fr.nrich.utils.TestUtils.getJsonAsMap;
import static fr.nrich.utils.TestUtils.getValueFromJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import fr.nrich.dao.APIConsumerDAO;
import fr.nrich.model.auth.APIConsumer;
import fr.nrich.model.auth.dto.JwtAuthenticationResponse;
import fr.nrich.utils.auth.GrantedAutorities;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
// ^ reinitialize database after each test
class AuthenticationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    APIConsumerDAO userDao;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    private RequestMappingHandlerMapping requestHandlerMapping;

    @BeforeEach
    public void before() {
        APIConsumer admin = new APIConsumer();
        admin.setUsername(ADMIN_USERNAME);
        admin.setPassword(passwordEncoder.encode(ADMIN_PASSWORD));
        admin.setAuthorities(List.of(GrantedAutorities.ADMIN));

        userDao.save(admin);

        APIConsumer user = new APIConsumer();
        user.setUsername(SIMPLE_USER_USERNAME);
        user.setPassword(passwordEncoder.encode(SIMPLE_USER_PASSWORD));

        userDao.save(user);
    }

    @Test
    public void registration() throws Exception {
        // Arrange
        String username = "newUser";
        String password = "thePassword";
        String form = createJsonString("username", username, "password", password);

        this.mockMvc.perform(post(REGISTER_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isCreated());

        authenticate(username, password);
        authenticateFails(username, WRONG_PASSWORD);
        authenticateFails("wrongUsername", password);
    }

    @Test
    public void authentication() throws Exception {
        // Admin account
        authenticate(ADMIN_USERNAME, ADMIN_PASSWORD);
        authenticateFails(ADMIN_USERNAME, WRONG_PASSWORD);
        authenticateFails(WRONG_USERNAME, ADMIN_PASSWORD);

        // Simple user account
        authenticate(SIMPLE_USER_USERNAME, SIMPLE_USER_PASSWORD);
        authenticateFails(SIMPLE_USER_USERNAME, WRONG_PASSWORD);
        authenticateFails(WRONG_USERNAME, SIMPLE_USER_PASSWORD);
    }

    @Test
    public void allIsUnauthorizedButAuthAndSwagger() throws Exception {
        // Act, assert
        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : this.requestHandlerMapping.getHandlerMethods()
                .entrySet()) {
            String url = entry.getKey().getPatternsCondition().getPatterns().iterator().next();
            if (!url.startsWith("/auth/") && !url.startsWith("/swagger-ui") && !url.equals("/swagger-ui.html"))
                this.mockMvc.perform(get(url)).andExpect(status().isUnauthorized());
        }
    }

    @Test
    public void shouldAllowAccessUsingToken() throws Exception {
        // Act, assert
        this.mockMvc.perform(get(SIMPLE_ENTRY_POINT).headers(adminAuthorizationHeader(mockMvc)))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldNotAllowAccessUsingRefreshToken() throws Exception {
        // Act, assert
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminRefreshToken(mockMvc));

        this.mockMvc.perform(get(SIMPLE_ENTRY_POINT).headers(headers)).andExpect(status().isUnauthorized());
    }

    @Test
    public void canRefreshToken() throws Exception {
        // Arrange
        JwtAuthenticationResponse authentication = authenticateAdmin(mockMvc);
        String oldToken = authentication.getToken();
        String form = createJsonString("refreshToken", authentication.getRefreshToken());
        Thread.sleep(1000); // the new token is same as old one if refreshing too fast

        // Act
        String result = this.mockMvc.perform(post(REFRESH_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        // Assert
        Map<String, String> resultMap = getJsonAsMap(result);
        assertThat(resultMap).hasFieldOrProperty("token");
        String newToken = resultMap.get("token");
        assertThat(newToken).hasSizeGreaterThan(0);
        assertThat(newToken).isNotEqualTo(oldToken);
    }

    @Test
    public void cannotRefreshInvalidToken() throws Exception {
        // Arrange
        String form = createJsonString("refreshToken", "invalidToken");

        // Act
        this.mockMvc.perform(post(REFRESH_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void refreshedTokenWorks() throws Exception {
        // Arrange
        String refreshToken = adminRefreshToken(mockMvc);
        String form = createJsonString("refreshToken", refreshToken);
        String newToken = getJsonAsMap(
                this.mockMvc.perform(post(REFRESH_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("token");

        // Act, assert
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(newToken);
        this.mockMvc.perform(get(SIMPLE_ENTRY_POINT).headers(headers)).andExpect(status().isOk());
    }

    @Test
    public void invalidateRefreshToken() throws Exception {
        // Arrange
        String refreshToken = adminRefreshToken(mockMvc);
        String form = createJsonString("refreshToken", refreshToken);

        // Act
        this.mockMvc.perform(put(REFRESH_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isNoContent());

        // Assert: cannot refresh again
        this.mockMvc.perform(post(REFRESH_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void cannotInvalidateInvalidRefreshToken() throws Exception {
        // Arrange
        String form = createJsonString("refreshToken", "invalidToken");

        // Act, assert
        this.mockMvc.perform(post(REFRESH_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isUnauthorized());
    }

    private void authenticate(String username, String password) throws Exception {
        // Arrange
        String form = createJsonString("username", username, "password", password);

        // Act
        String result = this.mockMvc.perform(post(AUTHENTICATION_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        // Assert
        assertThat(result).contains("\"refreshToken\"");
        assertThat(getValueFromJson("refreshToken", result)).hasSizeGreaterThan(0);
        assertThat(result).contains("\"token\"");
        assertThat(getValueFromJson("token", result)).hasSizeGreaterThan(0);
    }

    private void authenticateFails(String username, String password) throws Exception {
        // Arrange
        String form = createJsonString("username", username, "password", password);

        // Act
        this.mockMvc.perform(post(AUTHENTICATION_URL).contentType(MediaType.APPLICATION_JSON).content(form))
                .andExpect(status().isUnauthorized());
    }

}
