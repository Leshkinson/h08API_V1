import {IUser} from "../../ts/interfaces";

export class TokenMapper {
    public static prepareAccessModel(model: IUser) {
        return {
            id: model._id
        }
    }

    public static prepareRefreshModel(model: IUser) {
        return {
            id: model._id,
            email: model.email
        }
    }
}