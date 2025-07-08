package com.apis.auth_service.controllers;

import java.util.*;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import com.apis.auth_service.models.*;
import com.apis.auth_service.payload.request.*;
import com.apis.auth_service.payload.response.*;
import com.apis.auth_service.repository.*;
import com.apis.auth_service.security.jwt.JwtUtils;
import com.apis.auth_service.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final RestTemplate restTemplate = new RestTemplate();

  @Value("${account.service.base-url:http://192.168.1.7:8081}")
  private String accountServiceBaseUrl;

  private final AuthenticationManager authenticationManager;
  private final UserRepository userRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder encoder;
  private final JwtUtils jwtUtils;

  public AuthController(
      AuthenticationManager authenticationManager,
      UserRepository userRepository,
      RoleRepository roleRepository,
      PasswordEncoder encoder,
      JwtUtils jwtUtils) {
    this.authenticationManager = authenticationManager;
    this.userRepository = userRepository;
    this.roleRepository = roleRepository;
    this.encoder = encoder;
    this.jwtUtils = jwtUtils;
  }

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginRequest.getUsername(),
            loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities()
        .stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(
        jwt,
        userDetails.getId(),
        userDetails.getUsername(),
        userDetails.getEmail(),
        roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user
    User user = new User(
        signUpRequest.getUsername(),
        signUpRequest.getEmail(),
        encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null || strRoles.isEmpty()) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      for (String role : strRoles) {
        ERole eRole = switch (role.toLowerCase()) {
          case "admin" -> ERole.ROLE_ADMIN;
          case "mod" -> ERole.ROLE_MODERATOR;
          default -> ERole.ROLE_USER;
        };

        Role foundRole = roleRepository.findByName(eRole)
            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(foundRole);
      }
    }

    user.setRoles(roles);
    userRepository.save(user);

    // Notify external account service
    try {
      Map<String, Object> payload = Map.of("studentId", user.getId().toString());
      String url = accountServiceBaseUrl + "/accounts/";

      restTemplate.postForObject(url, payload, String.class);
    } catch (Exception e) {
      return ResponseEntity.internalServerError()
          .body(new MessageResponse("User registered, but failed to notify account service."));
    }

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  @GetMapping("/profile")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> getUserProfile(@AuthenticationPrincipal UserDetailsImpl userDetails) {
    User user = userRepository.findById(userDetails.getId())
        .orElseThrow(() -> new RuntimeException("Error: User not found."));

    return ResponseEntity.ok(new UserProfileResponse(
        user.getId(),
        user.getUsername(),
        user.getEmail()));
  }

  @PutMapping("/profile")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> updateUserProfile(
      @AuthenticationPrincipal UserDetailsImpl userDetails,
      @Valid @RequestBody UpdateProfileRequest updateRequest) {

    User user = userRepository.findById(userDetails.getId())
        .orElseThrow(() -> new RuntimeException("Error: User not found."));

    if (!user.getUsername().equals(updateRequest.getUsername()) &&
        userRepository.existsByUsername(updateRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (!user.getEmail().equals(updateRequest.getEmail()) &&
        userRepository.existsByEmail(updateRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    user.setUsername(updateRequest.getUsername());
    user.setEmail(updateRequest.getEmail());
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("Profile updated successfully!"));
  }
}
