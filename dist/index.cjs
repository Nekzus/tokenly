"use strict";var e=require("crypto"),t=require("jsonwebtoken");exports.Tokenly=class{constructor(e){this.currentToken=null,this.blacklistedTokens=new Set,this.deviceTokens=new Map,this.rotationCounts=new Map,this.revokedTokens=new Set,this.autoRotationInterval=null,this.secretAccess=process.env.JWT_SECRET_ACCESS||"default-secret-access",this.secretRefresh=process.env.JWT_SECRET_REFRESH||"default-secret-refresh",this.accessTokenExpiry=e?.accessTokenExpiry||process.env.ACCESS_TOKEN_EXPIRY||"15m",this.refreshTokenExpiry=e?.refreshTokenExpiry||process.env.REFRESH_TOKEN_EXPIRY||"7d",this.cookieOptions={httpOnly:!0,secure:"production"===process.env.NODE_ENV,sameSite:"strict",path:"/",maxAge:6048e5,...e?.cookieOptions},this.jwtOptions={algorithm:"HS512",issuer:"tokenly-auth",audience:"tokenly-client",...e?.jwtOptions},this.verifyOptions={algorithms:[this.jwtOptions.algorithm],issuer:this.jwtOptions.issuer,audience:this.jwtOptions.audience,clockTolerance:30},this.rotationConfig={enableAutoRotation:!0,rotationInterval:60,maxRotationCount:100,...e?.rotationConfig},this.securityConfig={enableFingerprint:!0,enableBlacklist:!0,maxDevices:5,revokeOnSecurityBreach:!0,...e?.securityConfig},this.eventListeners=new Map,this.tokenCache=new Map}formatDate(e){return new Date(1e3*e).toISOString()}decodeWithReadableDates(e,n){n||(n=t.decode(e));const{iat:r,exp:o,...i}=n;return{raw:e,payload:{...i,iat:r?new Date(1e3*r):void 0,exp:o?new Date(1e3*o):void 0}}}generateFingerprint(t){if(!t.userAgent||!t.ip)throw new Error("User agent and IP are required for fingerprint generation");const n=t.userAgent.replace(/^"|"$/g,""),r=t.ip.replace(/^"|"$/g,""),o={ua:n,ip:r,uaLength:n.length,ipLength:r.length,ipSegments:r.split(".").join(""),timestamp:Date.now(),additional:t.additionalData||""},i=JSON.stringify(o),s=e.createHash("sha256").update(i,"utf8").digest("hex");return console.log("DEBUG generateFingerprint - Cleaned Input:",{userAgent:n,ip:r,additionalData:t.additionalData}),s}revokeToken(e){if(e)try{const n=t.decode(e);this.revokedTokens.add(e),this.emit("tokenRevoked",{token:e,userId:n?.userId,timestamp:Date.now()})}catch(e){console.error("Error al revocar token:",e)}}isTokenBlacklisted(e){return this.securityConfig.enableBlacklist&&this.blacklistedTokens.has(e)}validatePayload(e){if(null===e||"object"!=typeof e)throw new Error("Payload must be an object");if(0===Object.keys(e).length)throw new Error("Payload cannot be empty");if(!Object.prototype.hasOwnProperty.call(e,"userId"))throw new Error("Payload must contain a userId");if(null===e.userId||void 0===e.userId)throw new Error("userId cannot be null or undefined");if("string"!=typeof e.userId||!e.userId.trim())throw new Error("userId cannot be empty");Object.entries(e).forEach((([e,t])=>{if(null==t)throw new Error(`Payload property '${e}' cannot be null or undefined`)}));if(JSON.stringify(e).length>8192)throw new Error("Payload size exceeds maximum allowed size")}generateAccessToken(e,n,r){this.validatePayload(e);const o={...e};if(this.securityConfig.enableFingerprint&&r){const t=this.generateFingerprint(r),n=e.userId;this.deviceTokens.has(n)||this.deviceTokens.set(n,new Set);const i=this.deviceTokens.get(n);if(i.size>=this.securityConfig.maxDevices&&!i.has(t))throw new Error("Maximum number of devices reached");i.add(t),o.fingerprint=t}const i=t.sign(o,this.secretAccess,{...this.jwtOptions,...n,expiresIn:this.accessTokenExpiry}),s=this.decodeWithReadableDates(i);return this.tokenCache.set(i,s),s}verifyAccessToken(e,n){if(console.log("DEBUG verifyAccessToken - Start"),console.log("DEBUG verifyAccessToken - Raw Context:",{userAgent:n?.userAgent?`"${n.userAgent}"`:void 0,ip:n?.ip?`"${n.ip}"`:void 0,additionalData:n?.additionalData}),this.revokedTokens.has(e))throw new Error("Token has been revoked");const r=t.verify(e,this.secretAccess,{...this.verifyOptions,ignoreExpiration:!1,clockTolerance:0});if(this.securityConfig.enableFingerprint&&n){const e=r.fingerprint;console.log("DEBUG verifyAccessToken - Stored Fingerprint:",e);const t=this.generateFingerprint(n);if(console.log("DEBUG verifyAccessToken - Generated Fingerprint:",t),e!==t)throw console.log("DEBUG verifyAccessToken - Fingerprint Mismatch Details:",{stored:e,current:t,storedContext:r.fingerprintContext,currentContext:n}),new Error("Invalid token fingerprint")}const o=this.decodeWithReadableDates(e,r);return this.tokenCache.set(e,o),o}generateRefreshToken(e,n){this.validatePayload(e);const r={...e};delete r.aud,delete r.iss,delete r.exp,delete r.iat;const o=t.sign(r,this.secretRefresh,{...this.jwtOptions,expiresIn:this.refreshTokenExpiry}),i=this.decodeWithReadableDates(o);return i.cookieConfig={name:"refresh_token",value:o,options:{...this.cookieOptions,...n}},i}verifyRefreshToken(e){const n=t.verify(e,this.secretRefresh,this.verifyOptions);return this.decodeWithReadableDates(e,n)}rotateTokens(e){if(!e||"string"!=typeof e)throw new Error("Invalid refresh token format");const t=this.verifyRefreshToken(e),{iat:n,exp:r,aud:o,iss:i,...s}=t.payload,a=e,c=this.rotationCounts.get(a)||0;if(c>=(this.rotationConfig.maxRotationCount||2))throw new Error("Maximum rotation count exceeded");return this.rotationCounts.set(a,c+1),{accessToken:this.generateAccessToken(s),refreshToken:this.generateRefreshToken(s)}}setToken(e){this.currentToken=e}getToken(){return this.currentToken}clearToken(){this.currentToken=null}isTokenExpiringSoon(e,n=5){try{const r=t.decode(e);if(!r||!r.exp)return!1;const o=1e3*r.exp,i=Date.now();return o-i<60*n*1e3}catch{return!1}}getTokenInfo(e){try{const n=t.decode(e);return n?{userId:n.userId,expiresAt:new Date(1e3*n.exp),issuedAt:new Date(1e3*n.iat),fingerprint:n.fingerprint}:null}catch{return null}}validateTokenFormat(e){try{const t=e.split(".");return 3===t.length&&t.every((e=>{try{return Buffer.from(e,"base64").toString(),!0}catch{return!1}}))}catch{return!1}}generateOneTimeToken(n,r="5m"){const o={purpose:n,nonce:e.randomBytes(16).toString("hex"),iat:Math.floor(Date.now()/1e3)};return t.sign(o,this.secretAccess,{expiresIn:r})}getEnhancedCookieOptions(){return{...this.cookieOptions,httpOnly:!0,secure:"production"===process.env.NODE_ENV,sameSite:"strict",path:"/",expires:new Date(Date.now()+6048e5),maxAge:6048e5}}verifyRefreshTokenEnhanced(e){if(!this.validateTokenFormat(e))throw new Error("Invalid token format");const t=this.verifyRefreshToken(e);if(this.isTokenExpiringSoon(e,60))throw new Error("Refresh token is about to expire");return t}on(e,t){this.eventListeners.has(e)||this.eventListeners.set(e,[]),this.eventListeners.get(e)?.push(t)}emit(e,t){const n=this.eventListeners.get(e);n?.length&&n.forEach((e=>{try{e(t)}catch(e){}}))}cacheToken(e,t){this.tokenCache.set(e,t),setTimeout((()=>{this.tokenCache.delete(e)}),3e5)}analyzeTokenSecurity(e){const n=t.decode(e,{complete:!0});if(!n)throw new Error("Invalid token");return{algorithm:n.header.alg,hasFingerprint:!!n.payload.fingerprint,expirationTime:new Date(1e3*n.payload.exp),issuedAt:new Date(1e3*n.payload.iat),timeUntilExpiry:1e3*n.payload.exp-Date.now(),strength:this.calculateTokenStrength(n)}}calculateTokenStrength(e){let t=0;"HS512"===e.header.alg?t+=2:"HS256"===e.header.alg&&(t+=1),e.payload.fingerprint&&(t+=2);const n=1e3*e.payload.exp-Date.now();return n<9e5?t+=1:n<36e5&&(t+=2),t<=2?"weak":t<=4?"medium":"strong"}enableAutoRotation(e={}){console.log("Enabling auto rotation...");const{checkInterval:t=50,rotateBeforeExpiry:n=1e3}=e;return this.autoRotationInterval&&clearInterval(this.autoRotationInterval),this.checkTokensExpiration(n),this.autoRotationInterval=setInterval((()=>{this.checkTokensExpiration(n)}),t),this.autoRotationInterval}disableAutoRotation(){this.autoRotationInterval&&(clearInterval(this.autoRotationInterval),this.autoRotationInterval=null)}checkTokensExpiration(e){Array.from(this.tokenCache.entries()).forEach((([n,r])=>{try{const r=t.decode(n);if(r?.exp){const t=1e3*r.exp-Date.now();t<e&&this.emit("tokenExpiring",{token:n,userId:r.userId,expiresIn:t})}}catch(e){}}))}enableAutoCleanup(e=36e5){setInterval((()=>{const e=Date.now();this.revokedTokens.forEach((n=>{try{const r=t.decode(n);r&&r.exp&&1e3*r.exp<e&&this.revokedTokens.delete(n)}catch{this.revokedTokens.delete(n)}}))}),e)}findTokenByFingerprint(e){for(const[,t]of this.deviceTokens.entries())if(t.has(e))return this.getToken();return null}async validateDeviceLimit(e,t){this.deviceTokens.has(e)||this.deviceTokens.set(e,new Set);const n=this.deviceTokens.get(e);if(n.size>=this.securityConfig.maxDevices&&!n.has(t))throw this.emit("maxDevicesReached",{userId:e,currentDevices:Array.from(n),maxDevices:this.securityConfig.maxDevices}),new Error("Maximum number of devices reached");n.add(t)}};
//# sourceMappingURL=index.cjs.map
