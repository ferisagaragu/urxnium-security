package org.urx.security

import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream

import java.io.ByteArrayInputStream
import java.io.InputStream

class CachedBodyServletInputStream(cachedBody: ByteArray?) : ServletInputStream() {
	private val cachedBodyInputStream: InputStream

	init {
		cachedBodyInputStream = ByteArrayInputStream(cachedBody)
	}

	override fun isFinished(): Boolean {
		return cachedBodyInputStream.available() == 0
	}

	override fun isReady(): Boolean {
		return true
	}

	override fun setReadListener(readListener: ReadListener) { }

	override fun read(): Int {
		return cachedBodyInputStream.read()
	}
}