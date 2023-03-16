package org.urx.security.interfaces

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import org.springframework.security.core.Authentication

interface SecurityAuthentication {
	fun validateUserName(userName: String): Boolean
	fun validateAuthorities(authorities: List<String>): Boolean
	fun customAuthentication(token: String, request: HttpServletRequest, response: HttpServletResponse): Authentication?
}