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
import { parseDiplomaData } from "../datasetParser";
import path from "path";
import { randomUUID } from "crypto";
import { Request } from "express";
import fs from 'fs';

parseDiplomaData(path.join(__dirname, "../../../../dataset/por-dataset.xlsx"));

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
			throw new Error("Cannot generate credential: (family_name, given_name, birthdate) is missing");
		}


		const diplomaEntries = parseDiplomaData(path.join(__dirname, "../../../../dataset/por-dataset.xlsx"));
		if (!diplomaEntries || diplomaEntries.length == 0) {
			throw new Error("No diploma entries found");
		}

		console.log("D Entries: ", diplomaEntries)
		console.log("Dataset birthdate = ", diplomaEntries[0].birthdate)
		console.log("user session birthdate = ", userSession.birthdate)
		console.log("Comparison = ", new Date(diplomaEntries[0].birthdate).toISOString() == new Date(userSession.birthdate).toISOString())
		const diplomaEntry = diplomaEntries.filter((diploma) =>
			String(diploma.family_name) == userSession.family_name &&
			String(diploma.given_name) == userSession.given_name &&
			new Date(diploma.birthdate as any).toISOString() == new Date(userSession.birthdate as any).toISOString()
		)[0];

		console.log("Diploma entry = ", diplomaEntry)
		if (!diplomaEntry) {
			console.error("Possibly raw data not found")
			throw new Error("Could not generate credential response");
		}

		const svgText = fs.readFileSync(path.join(__dirname, "../../../../public/images/template.svg"), 'utf-8');

		const rows: CategorizedRawCredentialViewRow[] = [
			{ name: "Legal Name", value: diplomaEntry.legal_name },
			{ name: "Legal Person Identifier", value: diplomaEntry.legal_person_identifier },
			{ name: "Full Powers", value: diplomaEntry.full_powers },
			{ name: "Effective From", value: diplomaEntry.effective_from_date },
			{ name: "Effective Until", value: diplomaEntry.effective_until_date },
		];
		const rowsObject: CategorizedRawCredentialView = { rows };

		const pathsWithValues = [
			{ path: "legal_name", value: diplomaEntry.legal_name },
			{ path: "legal_person_identifier", value: diplomaEntry.legal_person_identifier },
			{ path: "full_powers", value: diplomaEntry.full_powers },

			{ path: "effective_from_date", value: new Date(diplomaEntry.effective_from_date).toISOString() },
			{ path: "effective_until_date", value: new Date(diplomaEntry.effective_until_date).toISOString() },
		];
		const dataUri = generateDataUriFromSvg(svgText, pathsWithValues);

		const credentialView = {
			credential_id: diplomaEntry.certificateId,
			credential_supported_object: this.exportCredentialSupportedObject(),
			view: rowsObject,
			credential_image: dataUri,
		};
		return credentialView;
	}

	async generateCredentialResponse(userSession: AuthorizationServerState, request: Request, holderPublicKeyJwk: JWK): Promise<{ format: VerifiableCredentialFormat; credential: any; }> {
		if (!userSession?.family_name || !userSession?.given_name || !userSession?.birthdate) {
			throw new Error("Cannot generate credential: (family_name, given_name, birthdate) is missing");
		}
		const diplomaEntries = parseDiplomaData(path.join(__dirname, "../../../../dataset/por-dataset.xlsx"));
		if (!diplomaEntries || diplomaEntries.length == 0) {
			throw new Error("No entries found");
		}

		console.log("Entries = ", diplomaEntries)
		const diplomaEntry = diplomaEntries.filter((diploma) =>
			String(diploma.family_name) == userSession.family_name &&
			String(diploma.given_name) == userSession.given_name &&
			new Date(diploma.birthdate as any).toISOString() == new Date(userSession.birthdate as any).toISOString()
		)[0];

		if (!diplomaEntry) {
			console.error("diplomaEntry not found")
			throw new Error("Could not generate credential response");
		}

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
			"legal_person_identifier": String(diplomaEntry.legal_person_identifier),
			"legal_name": String(diplomaEntry.legal_name),
			"full_powers": String(diplomaEntry.full_powers),
			"expiry_date": new Date(diplomaEntry.expiry_date).toISOString(),
			"issuing_date": new Date(diplomaEntry.issuing_date).toISOString(),

			"effective_from_date": new Date(diplomaEntry.effective_from_date).toISOString(),
			"effective_until_date": diplomaEntry.effective_until_date && new Date(diplomaEntry.effective_until_date).toISOString(),
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

