// Ethio-Cyber Shield Frontend Configuration
const isLocalDevSeparatePort = typeof window !== 'undefined' && 
    (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') && 
    window.location.port === '5500';

const CONFIG = {
    // When served separately on port 5500 in local dev, point to local backend port 5000.
    // When deployed on Render (or accessed directly on port 5000), use relative '/api'
    API_BASE_URL: isLocalDevSeparatePort ? 'http://127.0.0.1:5000/api' : '/api',

    TOKEN_KEY: 'ecs_token',
    USER_KEY: 'ecs_user'
};
