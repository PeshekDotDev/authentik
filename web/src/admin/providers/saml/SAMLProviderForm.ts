import { renderForm } from "./SAMLProviderFormForm.js";

import { DEFAULT_CONFIG } from "#common/api/config";

import { type AkCryptoCertificateSearch } from "#admin/common/ak-crypto-certificate-search";
import { BaseProviderForm } from "#admin/providers/BaseProviderForm";

import { ProvidersApi, SAMLProvider, SpBindingEnum } from "@goauthentik/api";

import { customElement, state } from "lit/decorators.js";

@customElement("ak-provider-saml-form")
export class SAMLProviderFormPage extends BaseProviderForm<SAMLProvider> {
    @state()
    protected hasSigningKp = false;

    @state()
    protected hasSlsUrl = false;

    @state()
    protected hasPostBinding = false;

    @state()
    protected logoutMethod = "frontchannel_iframe";

    async loadInstance(pk: number): Promise<SAMLProvider> {
        const provider = await new ProvidersApi(DEFAULT_CONFIG).providersSamlRetrieve({
            id: pk,
        });
        this.hasSigningKp = !!provider.signingKp;
        this.hasSlsUrl = !!provider.slsUrl;
        this.hasPostBinding = provider.slsBinding === SpBindingEnum.Post;
        this.logoutMethod = provider.logoutMethod ?? "frontchannel_iframe";
        return provider;
    }

    async send(data: SAMLProvider): Promise<SAMLProvider> {
        // If SLS binding is not POST, ensure logout method is not backchannel
        if (data.slsBinding !== SpBindingEnum.Post && data.logoutMethod === "backchannel") {
            data.logoutMethod = "frontchannel_iframe";
        }

        if (this.instance) {
            return new ProvidersApi(DEFAULT_CONFIG).providersSamlUpdate({
                id: this.instance.pk,
                sAMLProviderRequest: data,
            });
        }
        return new ProvidersApi(DEFAULT_CONFIG).providersSamlCreate({
            sAMLProviderRequest: data,
        });
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

            // If switching to redirect binding, change logout method from backchannel if needed
            if (target.value === SpBindingEnum.Redirect && this.logoutMethod === "backchannel") {
                this.logoutMethod = "frontchannel_iframe";
            }

            this.requestUpdate();
        };

        return renderForm({
            provider: this.instance,
            setHasSigningKp,
            hasSigningKp: this.hasSigningKp,
            setHasSlsUrl,
            hasSlsUrl: this.hasSlsUrl,
            setSlsBinding,
            hasPostBinding: this.hasPostBinding,
        });
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-provider-saml-form": SAMLProviderFormPage;
    }
}
