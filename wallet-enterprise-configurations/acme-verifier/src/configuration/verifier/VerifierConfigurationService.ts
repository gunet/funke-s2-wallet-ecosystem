import { injectable } from "inversify";
import { OpenidForPresentationsConfiguration } from "../../services/types/OpenidForPresentationsConfiguration.type";
import { authorizationServerMetadataConfiguration } from "../../authorizationServiceConfiguration";
import { config } from "../../../config";
import { VerifierConfigurationInterface } from "../../services/interfaces";
import "reflect-metadata";
import { PresentationParserChain } from "../../vp_token/PresentationParserChain";
import { PublicKeyResolverChain } from "../../vp_token/PublicKeyResolverChain";
import * as mdl from '@auth0/mdl';
import { base64url } from "jose";


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

const sdJwtPorFields = [
	{
		"name": "Credential type",
		"path": ["$.vct"],
		"filter": {
			"type": "string",
			"enum": [
				"urn:credential:por"
			]
		}
	},
	{
		"name": "Legal Person Identifier",
		"path": ['$.legal_person_identifier'],
		"filter": {}
	},
	{
		"name": "Legal Name",
		"path": ['$.legal_name'],
		"filter": {}
	},
	{
		"name": "Full Powers",
		"path": ['$.full_powers'],
		"filter": {}
	},
	{
		"name": "Expiry Date",
		"path": ['$.expiry_date'],
		"filter": {}
	}
]

const sdJwtPorDescriptor = {
	"id": "POR",
	"format": {
		"vc+sd-jwt": {
			"alg": [
				"ES256"
			]
		},
	},
	"constraints": {
		"fields": sdJwtPorFields
	}
}


@injectable()
export class VerifierConfigurationService implements VerifierConfigurationInterface {

	getPublicKeyResolverChain(): PublicKeyResolverChain {
		return new PublicKeyResolverChain();
	}

	getPresentationParserChain(): PresentationParserChain {
		return new PresentationParserChain()
			.addParser({
				parse: async function (presentationRawFormat) {
					if (typeof presentationRawFormat != 'string') {
						return { error: "PARSE_ERROR" };
					}

					try {
						const parseRes = mdl.parse(base64url.decode(presentationRawFormat));
						if (parseRes.documents[0].docType != "eu.europa.ec.eudi.pid.1") {
							return { error: "PARSE_ERROR" };
						}
						return {
							credentialImage: config.url + "/images/card.png",
							credentialPayload: parseRes.documents[0].getIssuerNameSpace(parseRes.documents[0].issuerSignedNameSpaces[0])
						}
					}
					catch(err) {
						return { error: "PARSE_ERROR" };
					}
				},
			})
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
				"title": "Custom PID",
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
			{
				"id": "POR",
				"title": "Custom POR",
				"description": "Select the POR fields you want to request: Legal Person Identifier, Legal Name, Full Powers, Expiry Date",
				_selectable: true,
				"input_descriptors": [
					sdJwtPorDescriptor
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


