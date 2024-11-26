import { injectable } from "inversify";
import { OpenidForPresentationsConfiguration } from "../../services/types/OpenidForPresentationsConfiguration.type";
import { authorizationServerMetadataConfiguration } from "../../authorizationServiceConfiguration";
import { config } from "../../../config";
import { VerifierConfigurationInterface } from "../../services/interfaces";
import "reflect-metadata";
import { PresentationParserChain } from "../../vp_token/PresentationParserChain";
import { PublicKeyResolverChain } from "../../vp_token/PublicKeyResolverChain";



const sdJwtPidFields = [
	{
		"name": "Credential type",
		"path": ["$.vct"],
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

const sdJwtPidDescriptor = {
	"id": "VerifiableId",
	"format": {
		"vc+sd-jwt": {
			"alg": [
				"ES256"
			]
		},
	},
	"constraints": {
		"fields": sdJwtPidFields
	}
}


const mdocPidFields = [
	{
		"name": "Family Name",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['family_name']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Given Name",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['given_name']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Birthdate",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['birth_date']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Age over 18",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_over_18']"
		],
		"intent_to_retain": false
	},
]

const mdocPidDescriptor = {
	"id": "eu.europa.ec.eudi.pid.1",
	"format": {
		"mso_mdoc": {
			"alg": [
				"ES256"
			]
		},
	},
	"constraints": {
		"limit_disclosure": "required",
		"fields": mdocPidFields
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
				"id": "PID",
				"title": "SD-JWT PID",
				"description": "Required Fields: VC type, Given Name, Family Name & Birthdate",
				"input_descriptors": [
					sdJwtPidDescriptor
				]
			},
			{
				"id": "MdocPID",
				"title": "MDOC PID",
				"description": "Required Fields: Given Name, Family Name, Age Over 18, BirthDate",
				"input_descriptors": [
					mdocPidDescriptor
				]
			},
			{
				"id": "CustomVerifiableId",
				"title": "Custom Verifiable ID",
				"description": "Select the format and the fields you want to request.",
				_selectable: true,
				"input_descriptors": [
					{
						"id": undefined,
						"format": undefined,
						"constraints": {
							"limit_disclosure": "required",
							"fields": [
								...sdJwtPidFields,
								...mdocPidFields
							]
						}
					}
				]
			},
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


