require('dotenv').config();


const crypto = require('crypto');
const express = require('express');
const nodemailer = require('nodemailer');

const mailer = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
    }
});

const app = express();
const PORT = process.env.PORT || 5001;

app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Scholarship Webhook Receiver is running'
    });
});

app.post('/webhooks/scholarship', async (req, res) => {
    const signature = req.headers['x-webhook-signature'];
    const secret = process.env.WEBHOOK_SECRET;

    if (!signature || !secret) {
        return res.status(401).json({
            success: false,
            message: 'Webhook signature is missing'
        });
    }

    const [scheme, receivedSignature] = signature.split('=');

    if (scheme !== 'v1' || !receivedSignature) {
        return res.status(401).json({
            success: false,
            message: 'Invalid webhook signature format'
        });
    }

    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(req.rawBody, 'utf8')
        .digest('hex');

    let isValid = false;

    try {
        const receivedBuffer = Buffer.from(receivedSignature, 'hex');
        const expectedBuffer = Buffer.from(expectedSignature, 'hex');

        if (receivedBuffer.length === expectedBuffer.length) {
            isValid = crypto.timingSafeEqual(receivedBuffer, expectedBuffer);
        }
    } catch (error) {
        isValid = false;
    }

    if (!isValid) {
        console.log('❌ Invalid webhook signature');
        return res.status(403).json({
            success: false,
            message: 'Invalid webhook signature'
        });
    }

    console.log('\n========== VERIFIED WEBHOOK ==========');
    console.log('Event:', req.body.event);
    console.log('Application ID:', req.body.applicationId);
    console.log('Event ID:', req.body.id);
    console.log('Data:', req.body.data);
    console.log('======================================\n');
    const studentEmail = req.body.data?.studentEmail;

    if (!studentEmail) {
        console.error('Email not sent: student email missing from webhook payload');
    } else {
        try {
            const info = await mailer.sendMail({
                from: `"Scholarship Portal" <${process.env.GMAIL_USER}>`,
                to: studentEmail,
                subject: `Scholarship Application Update: ${req.body.event}`,
                html: `
                    <h2>Scholarship Application Notification</h2>
                    <p>A scholarship application event has occurred.</p>
                    <p><strong>Event:</strong> ${req.body.event || 'Unknown'}</p>
                    <p><strong>Application ID:</strong> ${req.body.applicationId || 'Not provided'}</p>
                    <p><strong>Event ID:</strong> ${req.body.id || 'Not provided'}</p>
                    <p><strong>Details:</strong> ${JSON.stringify(req.body.data || {})}</p>
                `
            });

            console.log('Email sent successfully:', info.messageId);
        } catch (error) {
            console.error('Email sending failed:', error.message);
        }
    }



    res.status(200).json({
        success: true,
        message: 'Webhook verified and received'
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Webhook receiver running on http://localhost:${PORT}`);
});
