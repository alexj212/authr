import api from './api';

class UserService {
    getPublicContent() {
        return api.get('/api/test/all');
    }

    getUserBoard() {
        return api.get('/api/test/user');
    }

    getModeratorBoard() {
        return api.get('/api/test/mod');
    }

    getAdminBoard() {
        return api.get('/api/test/admin');
    }
}

export default new UserService();
