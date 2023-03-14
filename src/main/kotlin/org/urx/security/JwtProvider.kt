package org.urx.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import org.springframework.util.StringUtils

import com.auth0.jwt.JWT
import com.auth0.jwt.interfaces.Claim
import com.auth0.jwt.interfaces.DecodedJWT

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SignatureException
import io.jsonwebtoken.UnsupportedJwtException

import jakarta.servlet.http.HttpServletRequest

import java.util.Date

import org.urx.security.properties.UrxniumSecurityProperties

import org.slf4j.LoggerFactory

@Component
class JwtProvider {

	@Autowired
	private lateinit var urxSecurityProperties: UrxniumSecurityProperties

	companion object {
		private val logger = LoggerFactory.getLogger(JwtProvider::class.java)
	}

	fun parseJwt(request: HttpServletRequest): String? {
		val headerAuth = request.getHeader(if (urxSecurityProperties.enableGraphql) "authorization" else "Authorization")
		return if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			headerAuth.substring(7, headerAuth.length)
		} else null
	}

	fun generateJwtToken(authentication: Authentication): MutableMap<String, Any> {
		val userPrinciple = authentication.principal as UserDetails
		val tokenAndExpiration: MutableMap<String, Any> = mutableMapOf()
		val expiration = Date(Date().time + urxSecurityProperties.jwtExpiration)
		val authorities: List<String> = userPrinciple.authorities.map { authority -> authority.authority }
		val claims: MutableMap<String, Any> = mutableMapOf()

		claims["authorities"] = authorities

		tokenAndExpiration["token"] = Jwts.builder()
			.setClaims(claims)
			.setSubject(userPrinciple.username)
			.setIssuedAt(Date())
			.setExpiration(expiration)
			.signWith(SignatureAlgorithm.HS512, urxSecurityProperties.jwtSecret)
			.compact()
		tokenAndExpiration["expiration"] = urxSecurityProperties.jwtExpiration
		tokenAndExpiration["expirationDate"] = expiration.toString()

		return tokenAndExpiration
	}

	fun generateJwtTokenNotExpiration(authentication: Authentication): Map<String, Any> {
		val userPrinciple = authentication.principal as UserDetails
		val tokenAndExpiration: MutableMap<String, Any> = mutableMapOf()
		val authorities: List<String> = userPrinciple.authorities.map { authority -> authority.authority }
		val claims: MutableMap<String, Any> = mutableMapOf()

		claims["authorities"] = authorities

		tokenAndExpiration["token"] = Jwts.builder()
			.setClaims(claims)
			.setSubject(userPrinciple.username)
			.setIssuedAt(Date())
			.signWith(SignatureAlgorithm.HS512, urxSecurityProperties.jwtSecret)
			.compact()

		return tokenAndExpiration
	}

	fun generateJwtTokenRefresh(authentication: Authentication): Map<String, Any> {
		val userPrinciple = authentication.principal as UserDetails
		val expiration = Date(Date().time + 31556900000)
		val token = generateJwtToken(authentication)
		val authorities: List<String> = userPrinciple.authorities.map { authority -> authority.authority }
		val claims: MutableMap<String, Any> = mutableMapOf()

		claims["authorities"] = authorities

		token["refreshToken"] = Jwts.builder()
			.setClaims(claims)
			.setSubject("${userPrinciple.username}_refresh")
			.setIssuedAt(Date())
			.setExpiration(expiration)
			.signWith(SignatureAlgorithm.HS512, urxSecurityProperties.jwtSecret)
			.compact()

		return token
	}

	fun refreshToken(token: String): MutableMap<String, Any> {
		val decodedJWT = JWT.decode(token)
		val tokenAndExpiration: MutableMap<String, Any> = mutableMapOf()
		val expiration = Date(Date().time + urxSecurityProperties.jwtExpiration)

		/*if (decodedJWT.expiresAt < Date()) {
			throw UnauthenticatedException("refresh token has expired")
		}*/

		/*if (!decodedJWT.subject.contains("_refresh")) {
			throw UnauthenticatedException("refresh token it's not valid")
		}*/

		val authorities = mutableMapOf<String, Any>()
		authorities["authorities"] = (decodedJWT.claims["authorities"] as Claim).asList(String::class.java)

		tokenAndExpiration["token"] = Jwts.builder()
			.setClaims(authorities)
			.setSubject(decodedJWT.subject.replace("_refresh", ""))
			.setIssuedAt(Date())
			.setExpiration(expiration)
			.signWith(SignatureAlgorithm.HS512, urxSecurityProperties.jwtSecret)
			.compact()
		tokenAndExpiration["expiration"] = urxSecurityProperties.jwtExpiration
		tokenAndExpiration["expirationDate"] = expiration.toString()

		return tokenAndExpiration
	}

	fun decodeJwt(token: String): DecodedJWT {
		return JWT.decode(token)
	}

	fun isJwtExpire(token: String): Boolean {
		return JWT.decode(token).expiresAt < Date()
	}

	fun getUserNameFromJwtToken(token: String): String {
		return Jwts.parser()
			.setSigningKey(urxSecurityProperties.jwtSecret)
			.parseClaimsJws(token)
			.body
			.subject
	}

	fun getAuthoritiesJwtToken(token: String): List<String> {
		return Jwts.parser()
			.setSigningKey(urxSecurityProperties.jwtSecret)
			.parseClaimsJws(token)
			.body["authorities"] as List<String>
	}

	fun validateJwtToken(authToken: String): Boolean {
		try {
			Jwts.parser().setSigningKey(urxSecurityProperties.jwtSecret).parseClaimsJws(authToken)
			return true
		} catch (e: SignatureException) {
			logger.error("Cannot set user authentication: Invalid JWT signature")
		} catch (e: MalformedJwtException) {
			logger.error("Cannot set user authentication: Invalid JWT token")
		} catch (e: ExpiredJwtException) {
			logger.error("Cannot set user authentication: Expired JWT token")
		} catch (e: UnsupportedJwtException) {
			logger.error("Cannot set user authentication: Unsupported JWT token")
		} catch (e: IllegalArgumentException) {
			logger.error("JCannot set user authentication: WT claims string is empty")
		}

		return false
	}

}