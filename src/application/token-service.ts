import jwt, {JwtPayload, Secret, SignOptions} from "jsonwebtoken";

const settings = {
    JWT_ACCESS_SECRET: "superpupersecret",
    JWT_REFRESH_SECRET: "superpupermegasecret",
    TOKEN_ACCESS_LIVE_TIME: {expiresIn: "10s"},
    TOKEN_REFRESH_LIVE_TIME: {expiresIn: "20s"},
}
export interface JWT extends JwtPayload {
    id: string;
    email: string;
}

export class TokenService {
    private readonly secretAccess: Secret;
    private readonly optionsAccess: SignOptions;
    private readonly secretRefresh: Secret;
    private readonly optionsRefresh: SignOptions;

    
    constructor() {
        this.optionsAccess = settings.TOKEN_ACCESS_LIVE_TIME;
        this.secretAccess = settings.JWT_ACCESS_SECRET;
        this.optionsRefresh = settings.TOKEN_REFRESH_LIVE_TIME;
        this.secretRefresh = settings.JWT_REFRESH_SECRET;
    }

    generateAccessToken(payload: object): string {
        return jwt.sign(payload, this.secretAccess, this.optionsAccess);
    }

    generateRefreshToken(payload: object):string {
        return jwt.sign(payload, this.secretRefresh, this.optionsRefresh);
    }

    getPayloadByAccessToken(token: string): string | JwtPayload | JWT {
        return jwt.verify(token, settings.JWT_ACCESS_SECRET)
    }

    getPayloadByRefreshToken(token: string): string | JwtPayload | JWT {
        return jwt.verify(token, settings.JWT_REFRESH_SECRET)
    }
}