package practice.jwt.domain.service;

import lombok.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.*;
import org.springframework.transaction.annotation.*;
import practice.jwt.domain.entity.*;
import practice.jwt.domain.repository.*;

@Service("simpleUserDetailService")
@Transactional
@AllArgsConstructor
public class SimpleUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String userName) {
        // userNameでデータベースからユーザーエンティティを検索する
        return userRepository.findByUserName(userName)
                             .map(SimpleLoginUser::new)
                             .orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }
}
