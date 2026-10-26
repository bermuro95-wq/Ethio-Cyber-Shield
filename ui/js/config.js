// Ethio-Cyber Shield Frontend Configuration
(function() {
    let apiBase = '/api';

    if (typeof window !== 'undefined') {
        const isFileProto = window.location.protocol === 'file:' || !window.location.hostname;
        const isLocalHost = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';
        const isSeparateDevPort = isLocalHost && window.location.port !== '' && window.location.port !== '5000';

        if (isFileProto) {
            // Direct file:// access in browser -> connect to production API
            apiBase = 'https://ethio-cyber-shield.onrender.com/api';
        } else if (isSeparateDevPort) {
            // Static dev server (Live Server 5500/5501, Vite, etc.) -> connect to local Flask backend
            apiBase = 'http://127.0.0.1:5000/api';
        } else {
            // Hosted by Flask backend or deployed on Render -> relative /api
            apiBase = '/api';
        }
    }

    const configObj = {
        API_BASE_URL: apiBase,
        TOKEN_KEY: 'ecs_token',
        USER_KEY: 'ecs_user'
    };

    if (typeof window !== 'undefined') {
        window.CONFIG = configObj;
    }
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = configObj;
    }
})();

var CONFIG = (typeof window !== 'undefined' && window.CONFIG) ? window.CONFIG : {
    API_BASE_URL: '/api',
    TOKEN_KEY: 'ecs_token',
    USER_KEY: 'ecs_user'
};
