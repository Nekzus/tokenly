/**
 * Helper function to get the real client IP from various headers
 * @param headers Object containing HTTP headers
 * @returns string Client IP address
 */
export declare function getClientIP(headers: Record<string, string | string[] | undefined>, defaultIP?: string): string;
