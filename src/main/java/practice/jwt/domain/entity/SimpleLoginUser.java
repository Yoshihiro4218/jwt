package practice.jwt.domain.entity;

import org.springframework.security.core.*;
import org.springframework.security.core.authority.*;

import java.util.*;

public class SimpleLoginUser extends org.springframework.security.core.userdetails.User {

    // Userエンティティ
    private User user;

    public User getUser() {
        return user;
    }

    public SimpleLoginUser(User user) {
        super(user.getName(), user.getPassword(), determineRoles(user.isAdmin()));
        this.user = user;
    }

    private static final List<GrantedAuthority> USER_ROLES = AuthorityUtils.createAuthorityList("ROLE_USER");
    private static final List<GrantedAuthority> ADMIN_ROLES = AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER");

    private static List<GrantedAuthority> determineRoles(boolean isAdmin) {
        return isAdmin ? ADMIN_ROLES : USER_ROLES;
    }
}
