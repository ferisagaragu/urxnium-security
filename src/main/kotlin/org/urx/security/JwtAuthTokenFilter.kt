package org.urx.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import org.urx.security.interfaces.SecurityAuthentication
import org.urx.security.properties.UrxniumSecurityProperties

import java.util.stream.Collectors

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
		val requestOut = CachedBodyHttpServletRequest(request)

		try {
			val jwt: String? = jwtProvider.parseJwt(request)
			val path = request.servletPath

			if (validateGraphqlExcludes(requestOut)) {
				filterChainResponse(requestOut, response, filterChain, false, true)
				return
			}

			if (jwt == null) {
				logger.error("Cannot set user authentication: Bearer token header is null: $path")
				filterChainResponse(requestOut, response, filterChain, false, false)
				return
			}

			val securityAuthenticationOut = securityAuthentication.customAuthentication(jwt, requestOut, response)

			if (securityAuthenticationOut != null) {
				SecurityContextHolder.getContext().authentication = securityAuthenticationOut
				filterChainResponse(requestOut, response, filterChain, true, false)
				return
			}

			if (!jwtProvider.validateJwtToken(jwt)) {
				filterChainResponse(requestOut, response, filterChain, false, false)
				return
			}

			if (!securityAuthentication.validateUserName(jwtProvider.getUserNameFromJwtToken(jwt))) {
				logger.error("Cannot set user authentication: UserName is not equals or not found: $path")
				filterChainResponse(requestOut, response, filterChain, false, false)
				return
			}

			if (!securityAuthentication.validateAuthorities(jwtProvider.getAuthoritiesJwtToken(jwt))) {
				logger.error("Cannot set user authentication: Authorities are not equals or not found: $path")
				filterChainResponse(requestOut, response, filterChain, false, false)
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

		filterChain.doFilter(requestOut, response)
	}

	private fun filterChainResponse(
		request: HttpServletRequest,
		response: HttpServletResponse,
		filterChain: FilterChain,
		customValidation: Boolean,
		excludeMethod: Boolean
	) {
		val path = request.servletPath

		if (customValidation) { //esta parte es para responder si el usuario hace una validation custom
			if (response.status == 200)  filterChain.doFilter(request, response)
			if (response.status == 401)  unauthorizedHandle.writeUnauthorizedResponse(request, response, false)
			return
		}

		if ( //aquí se valida la authentication de graphql
			urxSecurityProperties.enableGraphql &&
			!urxSecurityProperties.permitRequests.contains(path) &&
			(path == "/graphql" || path == "/graphiql") &&
			!excludeMethod
		) {
			unauthorizedHandle.writeUnauthorizedResponse(request, response, true)
		} else {
			filterChain.doFilter(request, response)
		}
	}

	private fun validateGraphqlExcludes(request: HttpServletRequest): Boolean {
		return if (
			request.method == "POST" &&
			urxSecurityProperties.enableGraphql &&
			request.servletPath == "/graphql"
		) {
			var out = false
			val body = request.reader.lines().collect(Collectors.joining())

			var compareBody = body.replace("\\n", "")
				.replace("\\r", "")
				.replace(" ", "")

			urxSecurityProperties.permitGraphqlMethods.forEach { it
				if (!out) {
					out = compareBody.contains(it)
				}
			} //Esta seccion valida que el metodo coincida con la exclusion

			return out
		} else {
			return false
		}
	}

}