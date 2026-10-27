import { describe, expect, it } from "vitest";

import { safeReturnPath } from "../src";

describe("safeReturnPath", () => {
  it.each([
    ["/", "/"],
    ["/lab/3", "/lab/3"],
    ["/lab/3?x=1#top", "/lab/3?x=1#top"],
    ["/a/./b/../c", "/a/c"],
  ])("keeps %s", (input, expected) => expect(safeReturnPath(input)).toBe(expected));

  it.each([
    null,
    undefined,
    "",
    "lab",
    "//evil.example",
    "/\\evil.example",
    "https://evil.example",
    "javascript:alert(1)",
    "/a b",
    "/a\nb",
    "/ x",
    "/%2e%2e//evil.example",
    "/a/../..//evil.example",
    "/x".repeat(2000),
    "/handoff",
    "/handoff/x",
    "/signin",
    "/signout?done=1",
  ])("replaces %j with the fallback", (input) => expect(safeReturnPath(input as string | null)).toBe("/"));

  it("uses the given fallback", () => expect(safeReturnPath("//x", "/home")).toBe("/home"));
});
