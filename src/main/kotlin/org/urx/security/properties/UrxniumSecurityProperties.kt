package org.urx.security.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urx.security")
class UrxniumSecurityProperties(
	val permitRequests: MutableList<String> = arrayListOf(),
	val permitGraphqlMethods: MutableList<String> = arrayListOf(),
	val enableGraphql: Boolean = false,
	val jwtSecret: String = "isDangerousGoAlong",
	val jwtExpiration: Int = 18000000
) {

	init {
		if (enableGraphql) {
			permitRequests.add("/graphiql/**") //Se añaden porque graphql funciona diferente y
			permitRequests.add("/graphql/**") //hay que agregar que se excluyan del JwtAuthEntryPoint
		}

		convertGraphqlExcludes()
	}

	private fun convertGraphqlExcludes() {
		val iterator = permitGraphqlMethods.listIterator()
		while (iterator.hasNext()) {
			val next = iterator.next()

			if (next.contains(".") && next.contains("query")) {
				iterator.set(next.replace(".", "\":\"{"))
			}
		}
	}

}