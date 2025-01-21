import { Headers } from '../types.js';

/**
 * Helper function to get the real client IP from various headers
 * @param headers Object containing HTTP headers
 * @param defaultIP Optional default IP if no headers found
 * @returns string Client IP address
 */
export function getClientIP(headers: Headers, defaultIP: string = '0.0.0.0'): string {
    if (!headers || typeof headers !== 'object') {
        return defaultIP;
    }

    const realIP = headers['x-real-ip'];
    if (typeof realIP === 'string' && realIP.trim()) {
        return realIP.trim();
    }

    const forwardedFor = headers['x-forwarded-for'];
    if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
        const ips = forwardedFor.split(',');
        return ips[0].trim() || defaultIP;
    }

    return defaultIP;
}