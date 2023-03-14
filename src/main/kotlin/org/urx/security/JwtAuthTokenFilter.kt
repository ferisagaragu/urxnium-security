package org.urx.security

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import org.urx.security.properties.UrxniumSecurityProperties
import org.urx.security.interfaces.SecurityAuthentication

@Component
class JwtAuthTokenFilter: OncePerRequestFilter() {

	@Autowired
	lateinit var jwtProvider: JwtProvider

	@Autowired
	lateinit var securityAuthentication: SecurityAuthentication

	@Autowired
	lateinit var authHelper: AuthHelper

	@Autowired
	lateinit var unauthorizedHandle: UnauthorizedHandle

	@Autowired
	lateinit var urxSecurityProperties: UrxniumSecurityProperties

	override fun doFilterInternal(
		request: HttpServletRequest,
		response: HttpServletResponse,
		filterChain: FilterChain
	) {
		try {
			val jwt: String? = jwtProvider.parseJwt(request)
			val path = request.servletPath

			if (jwt == null) {
				logger.error("Cannot set user authentication: Bearer token header is null: ${path}")
				filterChainResponse(request, response, filterChain, false)
				return
			}

			val securityAuthenticationOut = securityAuthentication.customAuthentication(jwt, request, response)

			if (securityAuthenticationOut != null) {
				SecurityContextHolder.getContext().authentication = securityAuthenticationOut
				filterChainResponse(request, response, filterChain, true)
				return
			}

			if (!jwtProvider.validateJwtToken(jwt)) {
				filterChainResponse(request, response, filterChain, false)
				return
			}

			if (!securityAuthentication.validateUserName(jwtProvider.getUserNameFromJwtToken(jwt))) {
				logger.error("Cannot set user authentication: UserName is not equals or not found: ${path}")
				filterChainResponse(request, response, filterChain, false)
				return
			}

			if (!securityAuthentication.validateAuthorities(jwtProvider.getAuthoritiesJwtToken(jwt))) {
				logger.error("Cannot set user authentication: Authorities are not equals or not found: ${path}")
				filterChainResponse(request, response, filterChain, false)
				return
			}

			val out = mutableMapOf<String, String>()
			val userName = jwtProvider.getUserNameFromJwtToken(jwt)
			val authorities = jwtProvider.getAuthoritiesJwtToken(jwt)?.map {
				authorities -> SimpleGrantedAuthority(authorities)
			}

			out["jwtToken"] = jwt

			val authentication = authHelper.generateAuthentication(userName, authorities?: listOf(), out)
			SecurityContextHolder.getContext().authentication = authentication
		} catch (e: Exception) {
			logger.error("Cannot set user authentication: {}", e)
		}

		filterChain.doFilter(request, response)
	}

	private fun filterChainResponse(
		request: HttpServletRequest,
		response: HttpServletResponse,
		filterChain: FilterChain,
		customValidation: Boolean
	) {
		val path = request.servletPath

		if (customValidation) {
			if (response.status == 200)  filterChain.doFilter(request, response)
			if (response.status == 401)  unauthorizedHandle.writeUnauthorizedResponse(request, response)
			return
		}

		if (
			urxSecurityProperties.enableGraphql &&
			!urxSecurityProperties.permitRequests.contains(path) &&
			(path == "/graphql" || path == "/graphiql")
		) {
			unauthorizedHandle.writeUnauthorizedResponse(request, response)
		} else {
			filterChain.doFilter(request, response)
		}
	}

}