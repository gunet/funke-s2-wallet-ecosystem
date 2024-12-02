import { injectable } from "inversify";
import { OpenidForPresentationsConfiguration } from "../../services/types/OpenidForPresentationsConfiguration.type";
import { authorizationServerMetadataConfiguration } from "../../authorizationServiceConfiguration";
import { config } from "../../../config";
import { VerifierConfigurationInterface } from "../../services/interfaces";
import "reflect-metadata";
import { PresentationParserChain } from "../../vp_token/PresentationParserChain";
import { PublicKeyResolverChain } from "../../vp_token/PublicKeyResolverChain";
import * as mdl from '@auth0/mdl';
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt } from "@sd-jwt/core";
import crypto from 'node:crypto';
import * as jose from 'jose';
import { generateDataUriFromSvg } from "../../lib/generateDataUriFromSvg";
import axios from "axios";
import { formatDateDDMMYYYY } from "../../lib/formatDate";



// Encoding the string into a Uint8Array
const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => {
		// return crypto.subtle.digest('SHA-256', encoder.encode(input)).then((v) => new Uint8Array(v));
		return new Promise((resolve, _reject) => {
			const hash = crypto.createHash('sha256');
			hash.update(input);
			resolve(new Uint8Array(hash.digest()));
		});
	},
	algorithm: HasherAlgorithm.Sha256
}

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
		},
		"intent_to_retain": false
	},
	{
		"name": "Given Name",
		"path": ['$.given_name'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Family Name",
		"path": ['$.family_name'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Birthdate",
		"path": ['$.birthdate'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Place of Birth",
		"path": ['$.place_of_birth.locality'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Birth Year",
		"path": ['$.age_birth_year'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Age in Years",
		"path": ['$.age_in_years'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Family Name at Birth",
		"path": ['$.birth_family_name'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Nationalities",
		"path": ['$.nationalities'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Address - Locality",
		"path": ['$.address.locality'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Address - Country",
		"path": ['$.address.country'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Address - Postal Code",
		"path": ['$.address.postal_code'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Address - Street Address",
		"path": ['$.address.street_address'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Issuing Country",
		"path": ['$.issuing_country'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Issuing Authority",
		"path": ['$.issuing_authority'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Age Equal or over 12",
		"path": ['$.age_equal_or_over.12'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Age Equal or over 14",
		"path": ['$.age_equal_or_over.14'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Age Equal or over 16",
		"path": ['$.age_equal_or_over.16'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Age Equal or over 18",
		"path": ['$.age_equal_or_over.18'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Age Equal or over 21",
		"path": ['$.age_equal_or_over.21'],
		"filter": {},
		"intent_to_retain": false
	}
]

const sdJwtPidDescriptor = {
	"id": "VerifiableId",
	"name": "PID",
	"purpose": "Present your SD-JWT PID",
	"format": {
		"vc+sd-jwt": {
			"sd-jwt_alg_values": ["ES256"],
			"kb-jwt_alg_values": ["ES256"]
		},
	},
	"constraints": {
		"limit_disclosure": "required",
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
		"name": "Family Name at Birth",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['family_name_birth']"
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
		"name": "Age over 12",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_over_12']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Age over 14",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_over_14']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Age over 16",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_over_16']"
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
	{
		"name": "Age over 21",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_over_21']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Age over 65",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_over_65']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Age in Years",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_in_years']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Birth Year",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['age_birth_year']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Birth Place",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['birth_place']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Nationality",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['nationality']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Resident Country",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['resident_country']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Resident Postal Code",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['resident_postal_code']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Resident City",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['resident_city']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Resident Street",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['resident_street']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Issuing Country",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['issuing_country']"
		],
		"intent_to_retain": false
	},
	{
		"name": "Issuing Authority",
		"path": [
			"$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
		],
		"intent_to_retain": false
	},
]

const mdocPidDescriptor = {
	"id": "eu.europa.ec.eudi.pid.1",
	"name": "MdocPID",
	"purpose": "Present your MDOC PID",
	"format": {
		"mso_mdoc": {
			"sd-jwt_alg_values": ["ES256"],
			"kb-jwt_alg_values": ["ES256"]
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
		},
		"intent_to_retain": false
	},
	{
		"name": "Legal Person Identifier",
		"path": ['$.legal_person_identifier'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Legal Name",
		"path": ['$.legal_name'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Full Powers",
		"path": ['$.full_powers'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Expiry Date",
		"path": ['$.expiry_date'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Effective From Date",
		"path": ['$.effective_from_date'],
		"filter": {},
		"intent_to_retain": false
	},
	{
		"name": "Effective Until Date",
		"path": ['$.effective_until_date'],
		"filter": {},
		"intent_to_retain": false
	}
]

const sdJwtPorDescriptor = {
	"id": "POR",
	"name": "Custom POR",
	"purpose": "Present your POR",
	"format": {
		"vc+sd-jwt": {
			"sd-jwt_alg_values": ["ES256"],
			"kb-jwt_alg_values": ["ES256"]
		},
	},
	"constraints": {
		"limit_disclosure": "required",
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
						const parseRes = mdl.parse(jose.base64url.decode(presentationRawFormat));
						if (parseRes.documents[0].docType != "eu.europa.ec.eudi.pid.1") {
							return { error: "PARSE_ERROR" };
						}
						return {
							credentialImage: config.url + "/images/card.png",
							credentialPayload: parseRes.documents[0].getIssuerNameSpace(parseRes.documents[0].issuerSignedNameSpaces[0])
						}
					}
					catch (err) {
						return { error: "PARSE_ERROR" };
					}
				},
			})
			.addParser({
				parse: async function (presentationRawFormat) {
					if (typeof presentationRawFormat != 'string') {
						return { error: "PARSE_ERROR" };
					}



					let credentialPayload = null;
					let credentialImage = null;

					try {
						if (presentationRawFormat.includes('~')) {
							const parsedCredential = await SdJwt.fromCompact<Record<string, unknown>, any>(presentationRawFormat)
								.withHasher(hasherAndAlgorithm)
								.getPrettyClaims();
							credentialPayload = parsedCredential;
							const vct = parsedCredential.vct;
							if (vct !== "https://example.bmi.bund.de/credential/pid/1.0" && vct !== "urn:eu.europa.ec.eudi:pid:1") {
								console.log('error', 'Wrong vct');
								return { error: "PARSE_ERROR" };
							}
							const pathsWithValues = [
								{ path: "family_name", value: parsedCredential.family_name },
								{ path: "given_name", value: parsedCredential.given_name },
								{ path: "birthdate", value: formatDateDDMMYYYY(parsedCredential.birthdate) },
								{ path: "exp", value: new Date(parsedCredential.exp * 1000).toLocaleDateString() }
							];
							// @ts-ignore
							const response = await axios.get(config.url + '/images/pid_template.svg');
							const svgText = response.data;
							const dataUri = generateDataUriFromSvg(svgText, pathsWithValues); // replaces all with empty string
							credentialImage = dataUri;
							return {
								credentialImage: credentialImage as string,
								credentialPayload: credentialPayload as any,
							}
						}
					}
					catch (err) {
						return { error: "PARSE_ERROR" };
					}
					return { error: "PARSE_ERROR" };

				},
			})
	}

	getPresentationDefinitions(): any[] {
		return [
			{
				"id": "PID",
				"title": "SD-JWT PID",
				"description": "Required Fields: Credential type, Given Name, Family Name, Birthdate, Place of Birth, Birth Year, Age in Years, Family Name at Birth, Nationalities, Address, Issuing Country, Issuing Authority",
				"input_descriptors": [
					sdJwtPidDescriptor
				]
			},
			{
				"id": "MdocPID",
				"title": "MDOC PID",
				"description": "Required Fields: Family Name, Given Name, Family Name at Birth, Birthdate, Age, Birth Year, Birth Place, Nationality, Resident Info, Issuing Country, Issuing Authority",
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
						"name": "Custom PID",
						"purpose": "Present your custom PID",
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
				"description": "Select the POR fields you want to request: Legal Person Identifier, Legal Name, Full Powers, Expiry Date, Effective From Date, Effective Until Date",
				_selectable: true,
				"input_descriptors": [
					sdJwtPorDescriptor
				]
			},
			{
				"id": "CombinedPidWithPor",
				"title": "PID with POR",
				"description": "Combined Presentation of PID and POR",
				"input_descriptors": [
					sdJwtPidDescriptor,
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


