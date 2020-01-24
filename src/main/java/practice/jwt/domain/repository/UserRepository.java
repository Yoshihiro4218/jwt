package practice.jwt.domain.repository;

import org.apache.ibatis.annotations.*;
import practice.jwt.domain.entity.*;

import java.util.*;

@Mapper
public interface UserRepository {
    Optional<User> findById(long userId);

    Optional<User> findByUserName(String userName);
}
