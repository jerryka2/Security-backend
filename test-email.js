// Test file for password reset email with EnergiPort branding
import 'dotenv/config';
import sendPasswordResetEmail from './utils/sendPasswordResetEmail.js';

const testEmail = async () => {
    try {
        console.log('Testing updated EnergiPort password reset email...');
        console.log('EMAIL_USER:', process.env.EMAIL_USER);
        console.log('CLIENT_URL:', process.env.CLIENT_URL);
        
        // Test with a sample token
        const testToken = 'energiport_test_token_123';
        await sendPasswordResetEmail('sumanka37@gmail.com', testToken);
        console.log('✅ EnergiPort email test successful!');
    } catch (error) {
        console.error('❌ Email test failed:', error.message);
        console.error('Full error:', error);
    }
};

testEmail();
