package org.urx.security

import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import org.slf4j.LoggerFactory

@Component //1.- aquí se validan los errores de seguridad
class JwtAuthEntryPoint(
	private val unauthorizedHandle: UnauthorizedHandle
): AuthenticationEntryPoint {

	private val logger = LoggerFactory.getLogger(JwtAuthEntryPoint::class.java)

	override fun commence(
		request: HttpServletRequest,
		response: HttpServletResponse,
		authException: AuthenticationException
	) {
		logger.error("Unauthorized error: {}", "${authException.message}:${request.servletPath!!}")
		unauthorizedHandle.writeUnauthorizedResponse(request, response, false)
	}

}