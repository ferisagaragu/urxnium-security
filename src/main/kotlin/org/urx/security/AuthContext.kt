package org.urx.security

import java.util.stream.Stream
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component

@Component
class AuthContext {

	val userName: String
		get() = SecurityContextHolder.getContext().authentication.name

	val authorities: Stream<SimpleGrantedAuthority>?
		get() {
			val auth = SecurityContextHolder.getContext().authentication;
			return auth.authorities.stream().map {
				SimpleGrantedAuthority(it.authority)
			}
		}

	val payload: Any?
		get() = SecurityContextHolder.getContext().authentication.details

}