import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const cookies = req.headers.cookie;
    const tokenMatch = cookies ? cookies.match(/reseller_token=([^;]+)/) : null;
    if (!tokenMatch) return res.status(401).json({ error: 'Not authenticated' });

    let user;
    try {
        user = jwt.verify(tokenMatch[1], process.env.JWT_SECRET);
    } catch (err) {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const { duration, note } = req.body;

    try {
        // Here you will make the fetch() call to SellAuth to generate the key
        // using process.env.SELLAUTH_API_KEY
        
        return res.status(200).json({ 
            success: true, 
            key: `OMNIS-${Math.random().toString(36).substring(2, 8).toUpperCase()}-${duration}D`
        });

    } catch (error) {
        console.error('Key Gen Error:', error);
        return res.status(500).json({ error: 'Failed to generate key' });
    }
}
