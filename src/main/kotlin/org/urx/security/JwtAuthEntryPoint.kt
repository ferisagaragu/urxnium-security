package org.urx.security


import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import org.urx.security.properties.UrxniumSecurityProperties

import com.fasterxml.jackson.databind.ObjectMapper

import org.slf4j.LoggerFactory

@Component //1.- aquí se validan los errores de seguridad
class JwtAuthEntryPoint(
	val urxniumSecurityProperties: UrxniumSecurityProperties,
	val unauthorizedHandle: UnauthorizedHandle
): AuthenticationEntryPoint {

	private val logger = LoggerFactory.getLogger(JwtAuthEntryPoint::class.java)

	override fun commence(
		request: HttpServletRequest,
		response: HttpServletResponse,
		authException: AuthenticationException
	) {
		val path = request.servletPath
		val body: MutableMap<String, Any> = HashMap()
		val mapper = ObjectMapper()

		if (urxniumSecurityProperties.permitRequests.contains(request.servletPath)) {
			response.contentType = MediaType.APPLICATION_JSON_VALUE
			response.status = HttpServletResponse.SC_OK

			body["status"] = HttpServletResponse.SC_OK
			body["path"] = path

			mapper.writeValue(response.outputStream, body)

			return
		}

		logger.error("Unauthorized error: {}", "${authException.message}:${request.servletPath!!}")
		unauthorizedHandle.writeUnauthorizedResponse(request, response)
	}

}