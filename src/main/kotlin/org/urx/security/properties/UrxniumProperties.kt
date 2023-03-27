package org.urx.security.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urx")
class UrxniumProperties(
	val language: String = "en"
)