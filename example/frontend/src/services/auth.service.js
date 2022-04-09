import api from "./api";
import Endpoints from "./endpoints";
import TokenService from "./token.service";


class AuthService {

    login({username, password}) {

        return api
            .post(Endpoints.LOGIN_API_ENDPOINT, {
                username,
                password
            })
            .then((response) => {

                if (response.data.access_token) {
                    TokenService.setUser(response.data);
                }

                return response.data;
            });
    }

    logout() {
        return api
            .post(Endpoints.LOGOFF_API_ENDPOINT,)
            .then((response) => {
                //console.log(`AuthService.LOGOFF_API_ENDPOINT`, response.data)
                TokenService.removeUser();
                return response.data;
            });
    }

    register({username, email, password}) {
        //console.log(`AuthService.register`, api)

        return api.post(Endpoints.REGISTER_API_ENDPOINT, {
            username,
            email,
            password
        }).then((response) => {
            //console.log(`AuthService.register`, response.data)

            if (response.data.access_token) {
                //console.log(`AuthService.1`)
                TokenService.setUser(response.data);
            }
            //console.log(`AuthService.2`)
            return response.data;
        });
    }
}

export default new AuthService();
