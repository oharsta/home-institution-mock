package home.api;

import io.micrometer.core.instrument.util.IOUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class PersonEndpoint {

    //https://open-education-api.github.io/specification/v4/docs.html#tag/persons/paths/~1persons~1{personId}/get
    @GetMapping("/persons/{personId}")
    public String persons(@PathVariable("personId") String personId, @AuthenticationPrincipal Jwt jw) throws IOException {
        return IOUtils.toString(new ClassPathResource("/data/person.json").getInputStream());
    }
}
