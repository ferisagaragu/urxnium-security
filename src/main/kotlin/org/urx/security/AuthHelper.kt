package org.urx.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired

import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

@Component
class AuthHelper {

	@Autowired
	lateinit var unauthorizedHandle: UnauthorizedHandle

	fun generateAuthentication(userName: String, authorities: List<GrantedAuthority>): Authentication {
		return generateAuthentication(userName, authorities, "")
	}

	fun generateAuthentication(userName: String, payload: String): Authentication {
		return generateAuthentication(userName, listOf(), payload)
	}

	fun generateAuthentication(userName: String): Authentication {
		return generateAuthentication(userName, listOf())
	}

	fun replyUnauthorized(
		request: HttpServletRequest,
		response: HttpServletResponse
	): Authentication {
		unauthorizedHandle.writeUnauthorizedResponse(request, response, false)
		return generateAuthentication("")
	}

	fun generateAuthentication(userName: String, authorities: List<GrantedAuthority>, details: Any?): Authentication {
		return object: Authentication {

			var authenticate = true

			override fun getAuthorities(): Collection<GrantedAuthority?> {
				return authorities
			}

			override fun getCredentials(): Collection<GrantedAuthority?> {
				return authorities
			}

			override fun getDetails(): Any? {
				return details
			}

			override fun isAuthenticated(): Boolean {
				return authenticate
			}

			override fun setAuthenticated(isAuthenticated: Boolean) {
				authenticate = isAuthenticated
			}

			override fun getName(): String {
				return userName
			}

			override fun getPrincipal(): Any {
				return object: UserDetails {
					override fun getAuthorities(): List<GrantedAuthority> {
						return authorities
					}

					override fun getPassword(): String {
						return ""
					}

					override fun getUsername(): String {
						return name
					}

					override fun isAccountNonExpired(): Boolean {
						return true
					}

					override fun isAccountNonLocked(): Boolean {
						return true
					}

					override fun isCredentialsNonExpired(): Boolean {
						return true
					}

					override fun isEnabled(): Boolean {
						return true
					}
				}
			}
		}
	}

}