import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

const authenticateOAuthTokenMock = vi.fn();

vi.mock("@/lib/mcp/oauth-auth", () => ({
  authenticateOAuthToken: (...args: unknown[]) =>
    authenticateOAuthTokenMock(...args),
}));

const authenticateApiKeyMock = vi.fn();

vi.mock("@/lib/api-key-auth", () => ({
  authenticateApiKey: (...args: unknown[]) => authenticateApiKeyMock(...args),
}));

vi.mock("@/lib/analytics/queries", () => ({
  getAnalyticsSummary: vi.fn().mockResolvedValue({
    totalRuns: 0,
    successRate: 0,
  }),
}));

import { GET } from "@/app/api/analytics/summary/route";
import { getAnalyticsSummary } from "@/lib/analytics/queries";

function request(authHeader: string | null): NextRequest {
  return {
    method: "GET",
    headers: new Headers(
      authHeader ? { Authorization: authHeader } : undefined
    ),
    nextUrl: { searchParams: new URLSearchParams() },
  } as unknown as NextRequest;
}

beforeEach(() => {
  vi.clearAllMocks();
  authenticateOAuthTokenMock.mockResolvedValue({
    authenticated: false,
    statusCode: 401,
    error: "Unauthorized",
  });
  authenticateApiKeyMock.mockResolvedValue({ authenticated: false });
});

describe("GET /api/analytics/summary auth (session-only -> dual auth)", () => {
  it("rejects when no credential resolves an organization", async () => {
    const res = await GET(request(null));
    expect(res.status).toBe(401);
    expect(getAnalyticsSummary).not.toHaveBeenCalled();
  });

  it("accepts a Bearer kh_ API key via authenticateApiKey", async () => {
    authenticateApiKeyMock.mockResolvedValueOnce({
      authenticated: true,
      userId: "user_key",
      organizationId: "org_from_key",
      apiKeyId: "key_1",
      scope: "mcp:read",
    });

    const res = await GET(request("Bearer kh_test_123"));
    expect(res.status).toBe(200);
    expect(authenticateApiKeyMock).toHaveBeenCalled();
    expect(getAnalyticsSummary).toHaveBeenCalledWith(
      "org_from_key",
      expect.anything(),
      undefined,
      undefined,
      undefined
    );
  });

  it("denies 403 when the API key scope lacks mcp:read", async () => {
    authenticateApiKeyMock.mockResolvedValueOnce({
      authenticated: true,
      userId: "user_key",
      organizationId: "org_from_key",
      apiKeyId: "key_1",
      scope: "",
    });

    const res = await GET(request("Bearer kh_test_123"));
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("insufficient_scope");
    expect(getAnalyticsSummary).not.toHaveBeenCalled();
  });

  it("keeps resolving org from an OAuth Bearer JWT", async () => {
    authenticateOAuthTokenMock.mockResolvedValueOnce({
      authenticated: true,
      userId: "user_oauth",
      organizationId: "org_from_jwt",
      scope: "mcp:read",
    });

    const res = await GET(request("Bearer fake-jwt"));
    expect(res.status).toBe(200);
    expect(getAnalyticsSummary).toHaveBeenCalledWith(
      "org_from_jwt",
      expect.anything(),
      undefined,
      undefined,
      undefined
    );
  });
});
