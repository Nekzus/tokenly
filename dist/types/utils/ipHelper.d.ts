import { Headers } from '../types.js';
/**
 * Helper function to get the real client IP from various headers
 * @param headers Object containing HTTP headers
 * @param defaultIP Optional default IP if no headers found
 * @returns string Client IP address
 */
export declare function getClientIP(headers: Headers, defaultIP?: string): string;
