import "#admin/applications/wizard/ak-wizard-title";
import "#elements/forms/FormGroup";

import { ApplicationWizardProviderForm } from "./ApplicationWizardProviderForm.js";

import { type AkCryptoCertificateSearch } from "#admin/common/ak-crypto-certificate-search";
import { renderForm, SAMLProviderFormContext } from "#admin/providers/saml/SAMLProviderFormForm";

import { SAMLProvider, SpBindingEnum } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { customElement, state } from "@lit/reactive-element/decorators.js";
import { html } from "lit";

@customElement("ak-application-wizard-provider-for-saml")
export class ApplicationWizardProviderSamlForm extends ApplicationWizardProviderForm<SAMLProvider> {
    label = msg("Configure SAML Provider");

    @state()
    hasSigningKp = false;

    @state()
    hasSlsUrl = false;

    @state()
    hasPostBinding = false;

    @state()
    backchannelPostLogout = false;

    get formValues() {
        const values = super.formValues;
        // If SLS binding is not POST, ensure backchannel post logout is disabled
        if (values.slsBinding !== SpBindingEnum.Post) {
            values.backchannelPostLogout = false;
        }
        return values;
    }

    renderForm() {
        const setHasSigningKp = (ev: InputEvent) => {
            const target = ev.target as AkCryptoCertificateSearch;
            if (!target) return;
            this.hasSigningKp = !!target.selectedKeypair;
        };

        const setHasSlsUrl = (ev: Event) => {
            const akTextInput = ev.currentTarget as HTMLElement & { value?: string };
            if (!akTextInput) return;

            const value = akTextInput.value || "";
            this.hasSlsUrl = !!value;
            this.requestUpdate();
        };

        const setSlsBinding = (ev: Event) => {
            const target = ev.target as HTMLInputElement;
            this.hasPostBinding = target.value === SpBindingEnum.Post;

            // If switching to redirect binding, disable backchannel post logout
            if (target.value === SpBindingEnum.Redirect) {
                this.backchannelPostLogout = false;
            }

            this.requestUpdate();
        };

        const context: SAMLProviderFormContext = {
            provider: this.wizard.provider
                ? {
                      ...(this.wizard.provider as SAMLProvider),
                      backchannelPostLogout: this.backchannelPostLogout,
                  }
                : { backchannelPostLogout: this.backchannelPostLogout },
            errors: this.wizard.errors?.provider ?? {},
            signingKp: {
                hasSigningKp: this.hasSigningKp,
                setHasSigningKp,
            },
            slsUrl: {
                hasSlsUrl: this.hasSlsUrl,
                setHasSlsUrl,
            },
            slsBinding: {
                hasPostBinding: this.hasPostBinding,
                setSlsBinding,
            },
        };

        return html` <ak-wizard-title>${this.label}</ak-wizard-title>
            <form id="providerform" class="pf-c-form pf-m-horizontal" slot="form">
                ${renderForm(context)}
            </form>`;
    }

    render() {
        if (!(this.wizard.provider && this.wizard.errors)) {
            throw new Error("SAML Provider Step received uninitialized wizard context.");
        }
        return this.renderForm();
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-application-wizard-provider-for-saml": ApplicationWizardProviderSamlForm;
    }
}
