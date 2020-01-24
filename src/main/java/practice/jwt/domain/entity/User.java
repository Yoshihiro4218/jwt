package practice.jwt.domain.entity;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    private Long id;
    @NonNull
    private String name;
    @NonNull
    private String password;
    @NonNull
    private String email;
    private boolean admin;
}
