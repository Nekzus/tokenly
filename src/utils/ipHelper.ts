/**
 * Helper function to get the real client IP from various headers
 * @param headers Object containing HTTP headers
 * @returns string Client IP address
 */
export function getClientIP(headers: Record<string, string | string[] | undefined>, defaultIP?: string): string {
    // Intentar X-Real-IP primero
    const realIP = headers['x-real-ip'];
    if (typeof realIP === 'string' && realIP.trim()) {
        return realIP.trim();
    }

    // Fallback a X-Forwarded-For si está disponible
    const forwardedFor = headers['x-forwarded-for'];
    if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
        return forwardedFor.split(',')[0].trim();
    }

    // Último fallback a IP proporcionada o vacía
    return defaultIP || '';
} 