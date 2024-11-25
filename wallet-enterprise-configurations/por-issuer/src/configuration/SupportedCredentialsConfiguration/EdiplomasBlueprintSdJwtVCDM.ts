import { config } from "../../../config";
import { VerifiableCredentialFormat } from "../../types/oid4vci";
import { CategorizedRawCredentialView, CategorizedRawCredentialViewRow } from "../../openid4vci/Metadata";
import { VCDMSupportedCredentialProtocol } from "../../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
// import { formatDateDDMMYYYY } from "../../lib/formatDate";
import { generateDataUriFromSvg } from "../../lib/generateDataUriFromSvg";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { CredentialView } from "../../authorization/types";
import { issuerSigner } from "../issuerSigner";
import { CredentialSigner } from "../../services/interfaces";
import { JWK } from "jose";
import { parseDataset } from "../datasetParser";
import path from "path";
import { randomUUID } from "crypto";
import { Request } from "express";
import fs from 'fs';

const pidDataset = parseDataset(path.join(__dirname, "../../../../dataset/test_identities.xlsx"), "PID");
const porDataset = parseDataset(path.join(__dirname, "../../../../dataset/test_identities.xlsx"), "POR");

console.log("Pid dataset = ", pidDataset);
console.log("Por dataset = ", porDataset);


export class EdiplomasBlueprintSdJwtVCDM implements VCDMSupportedCredentialProtocol {


	constructor() { }


	getId(): string {
		return "urn:credential:por";
	}
	getScope(): string {
		return "por";
	}

	getCredentialSigner(): CredentialSigner {
		return issuerSigner;
	}

	getFormat(): VerifiableCredentialFormat {
		return VerifiableCredentialFormat.VC_SD_JWT;
	}
	getTypes(): string[] {
		return ["VerifiableCredential", "VerifiableAttestation", "PowerOfRepresentation", this.getId()];
	}
	getDisplay() {
		return {
			name: "Power of Representation credential",
			description: "This is a Power of Representation credential",
			background_image: { uri: config.url + "/images/card.png" },
			background_color: "#4CC3DD",
			locale: 'en-US',
		}
	}


	async getProfile(userSession: AuthorizationServerState): Promise<CredentialView | null> {
		if (!userSession?.family_name || !userSession?.given_name || !userSession?.birthdate) {
			console.error("Cannot generate credential: (family_name, given_name, birthdate) is missing")
			throw new Error("Cannot generate credential: (family_name, given_name, birthdate) is missing");
		}


		const pidEntries = parseDataset(path.join(__dirname, "../../../../dataset/test_identities.xlsx"), "PID");
		console.log("Pid entries = ", pidEntries)
		if (!pidEntries || pidEntries.length == 0) {
			console.log("No pid entries");
			throw new Error("No pid entries found");
		}

		let pidEntry = null;
		try {

			console.log("Comp = ", pidEntries[0].birth_date.toISOString() == new Date(userSession.birthdate as any).toISOString())
			pidEntry = pidEntries.filter((diploma) =>
				String(diploma.family_name) == userSession.family_name &&
				String(diploma.given_name) == userSession.given_name &&
				diploma.birth_date instanceof Date &&
				diploma.birth_date.toISOString() == new Date(userSession.birthdate as any).toISOString()
			)[0];
		}
		catch(err) {
			console.error(err);
			throw new Error("Could not get profile");
		}



		console.log("pidEntry = ", pidEntry)
		if (!pidEntry) {
			console.error("Possibly raw data not found")
			throw new Error("Could not get profile");
		}

		const pidRecordId = pidEntry.Number;

		const porEntries = parseDataset(path.join(__dirname, "../../../../dataset/test_identities.xlsx"), "POR");

		console.log("Por entries = ", porEntries);
		if (!porEntries) {
			console.error("Couldnt fetch por entries")
			throw new Error("Could not get profile");
		}
		const porEntry = porEntries?.filter((por) => por.Number === pidRecordId)[0];

		console.log("Por entry = ", porEntry)
		if (!porEntry) {
			console.error("Couldnt fetch specific por entry with number " + String(pidRecordId))
			throw new Error("Could not get profile");
		}

		const svgText = fs.readFileSync(path.join(__dirname, "../../../../public/images/template.svg"), 'utf-8');

		const rows: CategorizedRawCredentialViewRow[] = [
			{ name: "Legal Name", value: porEntry.legal_name },
			{ name: "Legal Person Identifier", value: porEntry.legal_person_identifier },
			{ name: "Full Powers", value: porEntry.full_powers },
			{ name: "Effective From", value: porEntry.effective_from_date },
			{ name: "Effective Until", value: porEntry.effective_until_date },
		];

		console.log("rows = ", rows)
		const rowsObject: CategorizedRawCredentialView = { rows };

		try {
			const pathsWithValues = [
				{ path: "legal_name", value: porEntry.legal_name },
				{ path: "legal_person_identifier", value: porEntry.legal_person_identifier },
				{ path: "full_powers", value: porEntry.full_powers },
	
				{ path: "effective_from_date", value: new Date(porEntry.effective_from_date).toLocaleString() },
				{ path: "effective_until_date", value: new Date(porEntry.effective_until_date).toLocaleString() },
			];
	
			console.log("paths with values = ", pathsWithValues)
			const dataUri = generateDataUriFromSvg(svgText, pathsWithValues);
	
			const credentialView = {
				credential_id: randomUUID(),
				credential_supported_object: this.exportCredentialSupportedObject(),
				view: rowsObject,
				credential_image: dataUri,
			};
			return credentialView;
		}
		catch(err) {
			console.error(err);
			throw new Error("Could not get profile");
		}
	}

	async generateCredentialResponse(userSession: AuthorizationServerState, request: Request, holderPublicKeyJwk: JWK): Promise<{ format: VerifiableCredentialFormat; credential: any; }> {
		if (!userSession?.family_name || !userSession?.given_name || !userSession?.birthdate) {
			throw new Error("Cannot generate credential: (family_name, given_name, birthdate) is missing");
		}
		const pidEntries = parseDataset(path.join(__dirname, "../../../../dataset/test_identities.xlsx"), "PID");
		console.log("Pid entries = ", pidEntries)
		if (!pidEntries || pidEntries.length == 0) {
			console.log("No pid entries");
			throw new Error("No pid entries found");
		}

		let pidEntry = null;
		try {

			console.log("Comp = ", pidEntries[0].birth_date.toISOString() == new Date(userSession.birthdate as any).toISOString())
			pidEntry = pidEntries.filter((diploma) =>
				String(diploma.family_name) == userSession.family_name &&
				String(diploma.given_name) == userSession.given_name &&
				diploma.birth_date instanceof Date &&
				diploma.birth_date.toISOString() == new Date(userSession.birthdate as any).toISOString()
			)[0];
		}
		catch(err) {
			console.error(err);
			throw new Error("Could not get profile");
		}



		console.log("pidEntry = ", pidEntry)
		if (!pidEntry) {
			console.error("Possibly raw data not found")
			throw new Error("Could not get profile");
		}

		const pidRecordId = pidEntry.Number;

		const porEntries = parseDataset(path.join(__dirname, "../../../../dataset/test_identities.xlsx"), "POR");

		console.log("Por entries = ", porEntries);
		if (!porEntries) {
			console.error("Couldnt fetch por entries")
			throw new Error("Could not get profile");
		}
		const porEntry = porEntries?.filter((por) => por.Number === pidRecordId)[0];


		if (request.body?.vct != this.getId() || !userSession.scope || !userSession.scope.split(' ').includes(this.getScope())) {
			console.log("Not the correct credential");
			throw new Error("Not the correct credential");
		}

		const payload = {
			"cnf": {
				"jwk": holderPublicKeyJwk
			},
			"vct": this.getId(),
			"jti": `urn:credential:por:${randomUUID()}`,
			"legal_person_identifier": String(porEntry.legal_person_identifier),
			"legal_name": String(porEntry.legal_name),
			"full_powers": String(porEntry.full_powers),
			"expiry_date": new Date(porEntry.effective_until_date).toISOString(),
			"issuing_date": new Date(porEntry.effective_from_date).toISOString(),

			"effective_from_date": new Date(porEntry.effective_from_date).toISOString(),
			"effective_until_date": porEntry.effective_until_date && new Date(porEntry.effective_until_date).toISOString(),
		};

		const disclosureFrame = {
			legal_person_identifier: true,
			legal_name: true,
			full_powers: true,
		};

		const { jws } = await this.getCredentialSigner()
			.sign(payload, { typ: "JWT", vctm: this.metadata() }, disclosureFrame);

		const response = {
			format: this.getFormat(),
			credential: jws
		};

		return response;
	}

	public metadata(): any {
		return {
			"vct": this.getId(),
			"name": "Power of Representation credential",
			"description": "This is a Power of Representation credential",
			"display": [
				{
					"en-US": {
						"name": "Power of Representation credential",
						"rendering": {
							"simple": {
								"logo": {
									"uri": config.url + "/images/card.png",
									"uri#integrity": "sha256-c7fbfe45428aa2715f01065d812c9f6fd52f99c02e4018fb5761a7cbf4894257",
									"alt_text": "This is a Power of Representation credential",
								},
								"background_color": "#12107c",
								"text_color": "#FFFFFF"
							},
							"svg_templates": [
								{
									"uri": config.url + "/images/template.svg",
								}
							],
						}
					}
				}
			],
			"claims": [
				{
					"path": ["title"],
					"display": {
						"en-US": {
							"label": "Diploma Title",
							"description": "The title of the Diploma"
						}
					},
					"verification": "verified",
					"sd": "allowed"
				},
				{
					"path": ["grade"],
					"display": {
						"en-US": {
							"label": "Grade",
							"description": "Graduate's grade (0-10)"
						}
					},
					"verification": "verified",
					"sd": "allowed"
				},
				{
					"path": ["eqf_level"],
					"display": {
						"en-US": {
							"label": "EQF Level",
							"description": "The EQF level of the diploma according to https://europass.europa.eu/en/description-eight-eqf-levels"
						}
					},
					"verification": "verified",
					"sd": "allowed"
				},
				{
					"path": ["graduation_date"],
					"display": {
						"en-US": {
							"label": "Graduation Date",
							"description": "The graduation data"
						}
					},
					"verification": "verified",
					"sd": "allowed"
				},
			],
			"schema": {
				"$schema": "http://json-schema.org/draft-07/schema#",
				"type": "object",
				"properties": {
					"title": {
						"type": "string"
					},
					"grade": {
						"type": "string"
					},
					"eqf_level": {
						"type": "string",
					},
					"graduation_date": {
						"type": "string"
					}
				},
				"required": [],
				"additionalProperties": true
			}
		}

	}

	exportCredentialSupportedObject(): any {
		return {
			scope: this.getScope(),
			vct: this.getId(),
			format: this.getFormat(),
			display: [this.getDisplay()],
			cryptographic_binding_methods_supported: ["ES256"],
			credential_signing_alg_values_supported: ["ES256"],
			proof_types_supported: {
				jwt: {
					proof_signing_alg_values_supported: ["ES256"]
				}
			}
		}
	}

}

