package org.urx.security.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urx.security.develop")
class UrxniumSecurityDevProperties(
	val jwtUserName: String?,
	val jwtAuthorities: MutableList<String> = arrayListOf()
)