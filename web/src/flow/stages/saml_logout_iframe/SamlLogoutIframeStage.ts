import { BaseStage } from "#flow/stages/base";

import { SAMLIFrameChallenge, SAMLIFrameChallengeResponseRequest } from "@goauthentik/api";

import { html, TemplateResult } from "lit";
import { customElement } from "lit/decorators.js";

@customElement("ak-stage-saml-iframe-logout")
export class SamlLogoutIframeStage extends BaseStage<SAMLIFrameChallenge, SAMLIFrameChallengeResponseRequest> {
    firstUpdated() {
        const timeout = this.challenge.timeout || 5000;
        setTimeout(() => {
            this.submitForm();
        }, timeout);
    }

    render(): TemplateResult {
        return html`
            <div class="pf-c-login__main-body">
                <div class="pf-c-form">
                    <div class="pf-c-form__group">
                        <h2>Logging out of SAML providers...</h2>
                        <p>This will complete in ${this.challenge.timeout / 1000} seconds</p>
                    </div>
                    ${this.challenge.logoutUrls.map((logout, i) => {
                        if (logout.binding === "POST") {
                            return html`
                                <iframe name="saml-iframe-${i}" style="display: none;"></iframe>
                                <form
                                    id="saml-form-${i}"
                                    method="POST"
                                    action="${logout.url}"
                                    target="saml-iframe-${i}"
                                >
                                    <input
                                        type="hidden"
                                        name="SAMLRequest"
                                        value="${logout.samlRequest}"
                                    />
                                </form>
                                <script>
                                    document.getElementById("saml-form-${i}").submit();
                                </script>
                            `;
                        }
                        return html`<iframe src="${logout.url}" style="display: none;"></iframe>`;
                    })}
                </div>
            </div>
        `;
    }
}
