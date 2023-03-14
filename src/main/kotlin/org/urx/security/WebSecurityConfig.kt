package org.urx.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.stereotype.Component
import org.springframework.security.core.authority.SimpleGrantedAuthority

import org.urx.security.properties.UrxniumSecurityProperties
import org.urx.security.properties.UrxniumProperties
import org.urx.security.properties.UrxniumSecurityDevProperties

import org.slf4j.LoggerFactory

@Component
class WebSecurityConfig {

	private val logger = LoggerFactory.getLogger(WebSecurityConfig::class.java)

	@Autowired
	lateinit var jwtAuthEntryPoint: JwtAuthEntryPoint

	@Autowired
	lateinit var jwtAuthTokenFilter: JwtAuthTokenFilter

	@Autowired
	lateinit var jwtProvider: JwtProvider

	@Autowired
	lateinit var authHelper: AuthHelper

	@Autowired
	lateinit var urxProperties: UrxniumProperties

	@Autowired
	lateinit var urxSecurityProperties: UrxniumSecurityProperties

	@Autowired
	lateinit var urxSecurityDevProperties: UrxniumSecurityDevProperties

	@Bean //Esta dependencia solo sirve para que el usuario pueda encriptar una contraseña
	fun passwordEncoder(): PasswordEncoder {
		return BCryptPasswordEncoder()
	}

	@Bean //Esta dependencia solo se activa para que Spring boot sepa que ya no tiene que controlar la seguridad
	fun noopAuthenticationManager(): AuthenticationManager {
		return AuthenticationManager {
			throw AuthenticationServiceException(
				"Custom authentication is implemented"
			)
		}
	}

	@Bean //Aquí se validan los path que tienen que protegerse y con que dara seguridad Spring boot
	fun filterChain(http: HttpSecurity): SecurityFilterChain? {
		http.cors()
			.and()
			.csrf()
			.disable()
			.exceptionHandling()
			.authenticationEntryPoint(jwtAuthEntryPoint)
			.and()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeHttpRequests()
			.requestMatchers(
				*urxSecurityProperties.permitRequests.toTypedArray()
			).permitAll()
			.anyRequest()
			.authenticated()

		http.addFilterBefore(jwtAuthTokenFilter, UsernamePasswordAuthenticationFilter::class.java)
		logger.info("Security auto configuration is ENABLED")

		//This is only for develop mode
		printJwtTokenDevMode()

		return http.build()
	}

	private fun printJwtTokenDevMode() {
		if (urxProperties.developMode && urxSecurityDevProperties.jwtUserName != null) logger.warn(
			"Urx DEV mode: " +
				jwtProvider.generateJwtToken(authHelper.generateAuthentication(
					urxSecurityDevProperties.jwtUserName!!,
					urxSecurityDevProperties.jwtAuthorities.map { authorities -> SimpleGrantedAuthority(authorities) }
				)).toString()
		)
	}

}
