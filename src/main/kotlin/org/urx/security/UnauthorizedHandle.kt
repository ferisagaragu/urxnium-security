package org.urx.security

import org.springframework.http.MediaType
import org.springframework.stereotype.Component

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import com.fasterxml.jackson.databind.ObjectMapper

import org.urx.security.properties.UrxniumProperties

@Component
class UnauthorizedHandle(
	val urxProperties: UrxniumProperties
) {

	fun writeUnauthorizedResponse(
		request: HttpServletRequest,
		response: HttpServletResponse
	) {
		val path = request.servletPath
		val body: MutableMap<String, Any> = HashMap()
		val mapper = ObjectMapper()

		response.contentType = MediaType.APPLICATION_JSON_VALUE
		response.status = HttpServletResponse.SC_UNAUTHORIZED

		body["status"] = HttpServletResponse.SC_UNAUTHORIZED
		body["error"] = "Unauthorized"
		body["message"] = getUnauthorizedResource()
		body["path"] = path

		mapper.writeValue(response.outputStream, body)
	}

	private fun getUnauthorizedResource(): String {
		return when (urxProperties.language) {
			"es" -> "No estas autorizado para acceder a este recurso"
			else -> "You are not authorized to access this resource"
		}
	}

}