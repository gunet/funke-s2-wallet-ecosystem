import { injectable } from "inversify";
import { OpenidForPresentationsConfiguration } from "../../services/types/OpenidForPresentationsConfiguration.type";
import { authorizationServerMetadataConfiguration } from "../../authorizationServiceConfiguration";
import { config } from "../../../config";
import { VerifierConfigurationInterface } from "../../services/interfaces";
import "reflect-metadata";
import { PresentationParserChain } from "../../vp_token/PresentationParserChain";
import { PublicKeyResolverChain } from "../../vp_token/PublicKeyResolverChain";


const pidDescriptor = {
	"id": "VID",
	"format": { "vc+sd-jwt": { alg: [ 'ES256' ] }  },
	"constraints": {
		"fields": [
			{
				"name": "Credential type",
				"path": [
					"$.vct"
				],
				"filter": {
					"type": "string",
					"enum": [
						"https://example.bmi.bund.de/credential/pid/1.0",
						"urn:eu.europa.ec.eudi:pid:1"
					]
				}
			},
			{
				"name": "Given Name",
				"path": ['$.given_name'],
				"filter": {}
			},
			{
				"name": "Family Name",
				"path": ['$.family_name'],
				"filter": {}
			},
			{
				"name": "Birthdate",
				"path": ['$.birthdate'],
				"filter": {}
			}
		]
	}
}

@injectable()
export class VerifierConfigurationService implements VerifierConfigurationInterface {

	getPublicKeyResolverChain(): PublicKeyResolverChain {
		return new PublicKeyResolverChain();
	}

	getPresentationParserChain(): PresentationParserChain {
		return new PresentationParserChain();
	}

	getPresentationDefinitions(): any[] {
		return [
			{
				"id": "vid",
				"format": { "vc+sd-jwt": { alg: [ 'ES256' ] }  },
				"input_descriptors": [
					pidDescriptor,
				]
			}
		]
	}

	getConfiguration(): OpenidForPresentationsConfiguration {
		return {
			baseUrl: config.url,
			client_id: authorizationServerMetadataConfiguration.authorization_endpoint,
			redirect_uri: config.url + "/verification/direct_post",
			authorizationServerWalletIdentifier: "authorization_server",
		}
	}

}


	