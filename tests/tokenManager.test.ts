import { beforeEach, describe, expect, test } from "vitest";
import { TokenManager } from "../src/tokenManager";

let tokenManager: TokenManager;

beforeEach(() => {
	process.env.TOKEN_SECRET = "test-secret";
	tokenManager = new TokenManager();
});

describe("TokenManager", () => {
	test("should generate and verify a token", () => {
		const token = tokenManager.generateToken({ user: "test" });
		const verified = tokenManager.verifyToken(token);
		expect(verified).toHaveProperty("user", "test");
	});

	test("should return null for invalid token", () => {
		const invalidToken = "invalid.token.here";
		const verified = tokenManager.verifyToken(invalidToken);
		expect(verified).toBeNull();
	});
});
