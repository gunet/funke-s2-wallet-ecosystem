import { CONSENT_ENTRYPOINT, VERIFIER_PANEL_ENTRYPOINT } from "../../authorization/constants";
import { AuthenticationChainBuilder } from "../../authentication/AuthenticationComponent";
import { VerifierAuthenticationComponent } from "./VerifierAuthenticationComponent";
// import { InspectPersonalInfoComponent } from "./InspectPersonalInfoComponent";
import { AuthenticationMethodSelectionComponent } from "./AuthenticationMethodSelectionComponent";
import { GenericVIDAuthenticationComponent } from "../../authentication/authenticationComponentTemplates/GenericVIDAuthenticationComponent";
import { parseDataset } from "../datasetParser";
import path from "path";


const datasetName = "lsp_uc1_test_identities.xlsx";
parseDataset(path.join(__dirname, "../../../../dataset/" + datasetName), "POR");

export const authChain = new AuthenticationChainBuilder()
	// .addAuthenticationComponent(new ClientSelectionComponent("client-selection", CONSENT_ENTRYPOINT))
	.addAuthenticationComponent(new AuthenticationMethodSelectionComponent("auth-method", CONSENT_ENTRYPOINT))
	.addAuthenticationComponent(new GenericVIDAuthenticationComponent("vid-auth", CONSENT_ENTRYPOINT, {
		"family_name": { input_descriptor_constraint_field_name: "Family Name", parser: (val: any) => String(val) },
		"given_name": { input_descriptor_constraint_field_name: "Given Name", parser: (val: any) => String(val) },
		"birthdate": { input_descriptor_constraint_field_name: "Birthdate", parser: (val: any) => String(val) },
	}))
	// .addAuthenticationComponent(new InspectPersonalInfoComponent("2-ediplomas", CONSENT_ENTRYPOINT))
	.build();

export const verifierPanelAuthChain = new AuthenticationChainBuilder()
	.addAuthenticationComponent(new VerifierAuthenticationComponent("vid-verifier", VERIFIER_PANEL_ENTRYPOINT))
	.build();