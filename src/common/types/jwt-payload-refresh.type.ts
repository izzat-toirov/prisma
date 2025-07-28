import { JWTPload } from "./jwt-payload-refresh";

export type JWTPayloadWithRefreshToken = JWTPload & {refreshToken: string}