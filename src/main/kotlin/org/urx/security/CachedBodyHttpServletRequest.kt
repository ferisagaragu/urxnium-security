package org.urx.security

import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper

import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.util.Enumeration

import org.springframework.util.StreamUtils

class CachedBodyHttpServletRequest(request: HttpServletRequest): HttpServletRequestWrapper(request) {

	private val cachedBody: ByteArray

	init {
		val requestInputStream: InputStream = request.inputStream
		cachedBody = StreamUtils.copyToByteArray(requestInputStream)
	}

	override fun getInputStream(): ServletInputStream {
		return CachedBodyServletInputStream(cachedBody)
	}

	override fun getReader(): BufferedReader {
		val byteArrayInputStream = ByteArrayInputStream(cachedBody)
		return BufferedReader(InputStreamReader(byteArrayInputStream))
	}

	override fun getParameter(name: String?): String? {
		return this.request.getParameter(name)
	}

	override fun getParameterMap(): MutableMap<String, Array<String>>? {
		return this.request.parameterMap
	}

	override fun getParameterNames(): Enumeration<String>? {
		return this.request.parameterNames
	}

	override fun getParameterValues(name: String?): Array<String>? {
		return this.request.getParameterValues(name)
	}

}