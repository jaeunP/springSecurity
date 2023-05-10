package example.springsecurity.repository;


import example.springsecurity.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
//    @EntityGraph: 쿼리가 수행 될때 Eager 조회로 authorities를 가져옴
//    username을 기준으로 User 정보를 가져올때 권한 정보도 같이 가져옴
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}