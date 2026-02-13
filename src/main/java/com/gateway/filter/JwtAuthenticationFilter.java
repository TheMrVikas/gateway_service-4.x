package com.gateway.filter;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.gateway.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtil jwtUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// 1.
		String path = request.getRequestURI();
		System.out.println("path = "+path);

		// Public endpoint
		if (path.contains("/auth/login")) {
			filterChain.doFilter(request, response);
			return;
		}

		//
		String authHeader = request.getHeader("Authorization");

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			sendError(response, "Missing or Invalid Authorization Header");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		String token = authHeader.substring(7);

		if (!jwtUtil.isTokenValid(token)) {
			sendError(response, "Invalid Token");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		String username = jwtUtil.extractUsername(token);
		String role = jwtUtil.extractRole(token);
		System.out.println("username="+username);
		System.out.println("role="+role);
		

		List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role.trim()));
		System.out.println("Role from token: " + role);

		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null,
				authorities);

		SecurityContextHolder.getContext().setAuthentication(authentication);

		filterChain.doFilter(request, response);
	}

	private void sendError(HttpServletResponse response, String message) throws IOException {

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");

		response.getWriter().write("""
				    {
				      "status": 401,
				      "error": "Unauthorized",
				      "message": "%s"
				    }
				""".formatted(message));
	}

}
