package jwtg.springjwt.service;

import jwtg.springjwt.dto.JoinDTO;
import jwtg.springjwt.entity.UserEntity;
import jwtg.springjwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class JoinService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Transactional
    public void joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
            throw new IllegalArgumentException("이미 존재하는 아이디입니다.");
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);

        data.setPassword(bCryptPasswordEncoder.encode(password));

        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
