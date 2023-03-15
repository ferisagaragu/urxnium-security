package org.urx.security

import org.springframework.http.MediaType
import org.springframework.stereotype.Component

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import com.fasterxml.jackson.databind.ObjectMapper

import org.urx.security.properties.UrxniumProperties

@Component
class UnauthorizedHandle(
	private val urxProperties: UrxniumProperties
) {

	fun writeUnauthorizedResponse(
		request: HttpServletRequest,
		response: HttpServletResponse,
		isGraphQL: Boolean
	) {
		val path = request.servletPath
		val body: MutableMap<String, Any> = HashMap()
		val mapper = ObjectMapper()

		if (isGraphQL) {
			response.contentType = MediaType.APPLICATION_JSON_VALUE
			response.status = HttpServletResponse.SC_OK

			val erros = mutableListOf<Any>()
			val error = mutableMapOf<String, Any>()
			val extensions = mutableMapOf<String, String>()

			extensions["classification"] = "UNAUTHORIZED"

			error["message"] = getUnauthorizedResource()
			error["locations"] = listOf<String>()
			error["path"] = mutableListOf(path)
			error["extensions"] = extensions
			erros.add(error)
			body["errors"] = erros

			mapper.writeValue(response.outputStream, body)
			return
		}

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