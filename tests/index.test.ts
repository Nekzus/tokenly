import { describe, expect, test } from "vitest";
import { TokenManager } from "../src";

describe("Tokenly Export", () => {
	test("TokenManager should be exported", () => {
		expect(TokenManager).toBeDefined();
	});
});
