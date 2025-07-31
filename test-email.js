// Test file for password reset email with CarePoint branding
import 'dotenv/config';
import sendPasswordResetEmail from './utils/sendPasswordResetEmail.js';

const testEmail = async () => {
    try {
        console.log('Testing updated CarePoint password reset email...');
        console.log('EMAIL_USER:', process.env.EMAIL_USER);
        console.log('CLIENT_URL:', process.env.CLIENT_URL);
        
        // Test with a sample token
        const testToken = 'carepoint_test_token_123';
        await sendPasswordResetEmail('karundixit5@gmail.com', testToken);
        console.log('✅ CarePoint email test successful!');
    } catch (error) {
        console.error('❌ Email test failed:', error.message);
        console.error('Full error:', error);
    }
};

testEmail();
