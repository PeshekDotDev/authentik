/**
 * Multi-tab session management utilities.
 *
 * This module provides utilities for coordinating session resumption
 * across multiple browser tabs when a user's authentik session expires.
 */

import { DEFAULT_CONFIG } from "#common/api/config";
import { PendingOAuth2RequestInfo } from "#common/ws/events";

/**
 * Key used to store the tab ID in sessionStorage.
 * Each tab gets a unique ID that persists for the lifetime of that tab.
 */
const TAB_ID_KEY = "authentik_tab_id";

/**
 * Key used to store pending authorization request info in sessionStorage.
 * This stores the OAuth2 parameters that were being requested when
 * the session expired.
 */
const PENDING_AUTH_KEY = "authentik_pending_auth";

/**
 * Generate a unique tab ID.
 * Uses crypto.randomUUID if available, falls back to timestamp + random.
 */
function generateTabId(): string {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Get or create a unique ID for the current tab.
 * The ID is stored in sessionStorage so it persists across page reloads
 * but is unique to each tab.
 */
export function getTabId(): string {
    let tabId = sessionStorage.getItem(TAB_ID_KEY);
    if (!tabId) {
        tabId = generateTabId();
        sessionStorage.setItem(TAB_ID_KEY, tabId);
    }
    return tabId;
}

/**
 * Information about a pending OAuth2 authorization request.
 */
export interface PendingAuthInfo {
    /** The client_id of the OAuth2 provider */
    clientId: string;
    /** The full URL that was being accessed */
    originalUrl: string;
    /** Timestamp when this was stored */
    timestamp: number;
}

/**
 * Store information about a pending OAuth2 authorization request.
 * This is called when the current tab detects that the user needs to
 * re-authenticate.
 */
export function storePendingAuth(clientId: string): void {
    const info: PendingAuthInfo = {
        clientId,
        originalUrl: window.location.href,
        timestamp: Date.now(),
    };
    sessionStorage.setItem(PENDING_AUTH_KEY, JSON.stringify(info));
}

/**
 * Get information about a pending OAuth2 authorization request.
 * Returns null if there is no pending request or if it's too old (> 1 hour).
 */
export function getPendingAuth(): PendingAuthInfo | null {
    const stored = sessionStorage.getItem(PENDING_AUTH_KEY);
    if (!stored) {
        return null;
    }

    try {
        const info: PendingAuthInfo = JSON.parse(stored);
        // Expire after 1 hour
        if (Date.now() - info.timestamp > 60 * 60 * 1000) {
            sessionStorage.removeItem(PENDING_AUTH_KEY);
            return null;
        }
        return info;
    } catch {
        sessionStorage.removeItem(PENDING_AUTH_KEY);
        return null;
    }
}

/**
 * Clear the pending authorization request.
 * Called after successfully resuming the flow.
 */
export function clearPendingAuth(): void {
    sessionStorage.removeItem(PENDING_AUTH_KEY);
}

/**
 * Find a matching pending request for the current tab.
 * Returns the pending request that matches this tab's ID or client_id.
 */
export function findMatchingPendingRequest(
    pendingRequests: PendingOAuth2RequestInfo[],
): PendingOAuth2RequestInfo | null {
    const tabId = getTabId();
    const pendingAuth = getPendingAuth();

    // First, try to find a request that matches this tab's ID
    const tabMatch = pendingRequests.find((req) => req.tab_id === tabId);
    if (tabMatch) {
        return tabMatch;
    }

    // Fall back to matching by client_id if we have pending auth info
    if (pendingAuth) {
        const clientMatch = pendingRequests.find(
            (req) => req.client_id === pendingAuth.clientId,
        );
        if (clientMatch) {
            return clientMatch;
        }
    }

    return null;
}

/**
 * Interface for the pending requests API response.
 */
interface PendingRequestsResponse {
    pending_requests: Array<{
        request_id: string;
        client_id: string;
        provider_name: string;
        application_name: string | null;
        redirect_uri: string;
        authorization_url: string;
    }>;
}

/**
 * Interface for the resume API response.
 */
interface ResumeResponse {
    authorization_url: string;
    request_id: string;
}

/**
 * Fetch the authorization URL to resume a pending OAuth2 request.
 * This calls the backend API to get the full authorization URL
 * with all the original parameters.
 */
export async function resumePendingRequest(
    requestId: string,
): Promise<string | null> {
    try {
        const response = await fetch(
            `${DEFAULT_CONFIG.basePath}/oauth2/pending_requests/${requestId}/resume/`,
            {
                method: "GET",
                credentials: "include",
                headers: {
                    Accept: "application/json",
                },
            },
        );

        if (!response.ok) {
            console.error("Failed to resume pending request:", response.status);
            return null;
        }

        const data: ResumeResponse = await response.json();
        return data.authorization_url;
    } catch (error) {
        console.error("Error resuming pending request:", error);
        return null;
    }
}

/**
 * Fetch all pending OAuth2 requests for the current device.
 */
export async function fetchPendingRequests(): Promise<PendingRequestsResponse["pending_requests"]> {
    try {
        const response = await fetch(
            `${DEFAULT_CONFIG.basePath}/oauth2/pending_requests/`,
            {
                method: "GET",
                credentials: "include",
                headers: {
                    Accept: "application/json",
                },
            },
        );

        if (!response.ok) {
            console.error("Failed to fetch pending requests:", response.status);
            return [];
        }

        const data: PendingRequestsResponse = await response.json();
        return data.pending_requests;
    } catch (error) {
        console.error("Error fetching pending requests:", error);
        return [];
    }
}

/**
 * Handle session authenticated event for multi-tab resumption.
 * This is called when another tab successfully authenticates.
 *
 * @param pendingRequests - List of pending OAuth2 requests from the WebSocket message
 * @param isHidden - Whether this tab is currently hidden
 * @returns The URL to redirect to, or null if the page should just reload
 */
export async function handleSessionAuthenticated(
    pendingRequests: PendingOAuth2RequestInfo[],
    isHidden: boolean,
): Promise<string | null> {
    // Only process if this tab is hidden (another tab completed auth)
    if (!isHidden) {
        return null;
    }

    console.debug("authentik/multitab: Processing session authenticated event", {
        pendingCount: pendingRequests.length,
        tabId: getTabId(),
    });

    // Find a matching pending request for this tab
    const matchingRequest = findMatchingPendingRequest(pendingRequests);

    if (matchingRequest) {
        console.debug("authentik/multitab: Found matching pending request", {
            requestId: matchingRequest.request_id,
            provider: matchingRequest.provider_name,
        });

        // Get the authorization URL from the backend
        const authUrl = await resumePendingRequest(matchingRequest.request_id);

        if (authUrl) {
            console.debug("authentik/multitab: Redirecting to resume OAuth2 flow", {
                authUrl,
            });
            clearPendingAuth();
            return authUrl;
        }
    }

    // No matching request found, or couldn't get auth URL
    // Fall back to simple page reload
    console.debug("authentik/multitab: No matching pending request, reloading page");
    return null;
}
