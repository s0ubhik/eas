class EAS {
    static async encrypt(data, key) {
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(key.padEnd(32).substring(0, 32)),
            { name: 'AES-CBC', length: 256 },
            false,
            ['encrypt']
        );
        
        const iv = crypto.getRandomValues(new Uint8Array(16));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            cryptoKey,
            new TextEncoder().encode(data)
        );
        
        return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(encrypted)));
    }
    
    static async decrypt(encryptedData, key) {
        const decodedData = atob(encryptedData);
        const iv = new Uint8Array(decodedData.slice(0, 16).split('').map(c => c.charCodeAt(0)));
        const encrypted = new Uint8Array(decodedData.slice(16).split('').map(c => c.charCodeAt(0)));
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(key.padEnd(32).substring(0, 32)),
            { name: 'AES-CBC', length: 256 },
            false,
            ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            cryptoKey,
            encrypted
        );
        
        return new TextDecoder().decode(decrypted);
    }
}

async function x()
{
    const x = await EAS.encrypt("Hello", "hello");
    console.log(x)
}

x();