import {IToken} from "../ts/interfaces";
import {TokenModel} from "../models/token-model";
import {Model, RefType, SortOrder} from "mongoose";

export class TokenRepository {
    private tokenModel: Model<IToken>

    constructor() {
        this.tokenModel = TokenModel;
    }

    public async createToken(token: string): Promise<IToken> {
        return this.tokenModel.create(token)
    }

    public async findToken(token: string): Promise<IToken | null> {
        return this.tokenModel.findOne({"token": token})
    }
}