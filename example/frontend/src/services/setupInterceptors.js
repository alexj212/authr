import axiosInstance from "./api";
import Endpoints from "./endpoints";
import TokenService from "./token.service";


const setup = (store) => {
    axiosInstance.interceptors.request.use(
        (config) => {
            const token = TokenService.getLocalAccessToken();
            console.log('interceptors.request', token);

            if (token) {
                config.headers["Authorization"] = 'Bearer ' + token;  // for Spring Boot back-end
                // config.headers["x-access-token"] = token; // for Node.js Express back-end
            }
            return config;
        },
        (error) => {
            return Promise.reject(error);
        }
    );

    axiosInstance.interceptors.response.use(
        (res) => {
            console.log('interceptors.response', res);
            return res;
        },
        async (err) => {
            const originalConfig = err.config;

            if (originalConfig.url !== Endpoints.LOGIN_API_ENDPOINT && err.response) {
                // Access Token was expired
                if (err.response.status === 401 && !originalConfig._retry) {
                    originalConfig._retry = true;

                    try {
                        const rs = await axiosInstance.post(Endpoints.REFRESH_API_ENDPOINT, {
                            refreshToken: TokenService.getLocalRefreshToken(),
                        });

                        const {accessToken} = rs.data;
                        console.log('store.dispatch( \'auth/refreshToken.response\')', accessToken);
                        store.dispatch('auth/refreshToken', accessToken);
                        TokenService.updateLocalAccessToken(accessToken);

                        return axiosInstance(originalConfig);
                    } catch (_error) {
                        return Promise.reject(_error);
                    }
                }
            }

            return Promise.reject(err);
        }
    );
};

export default setup;