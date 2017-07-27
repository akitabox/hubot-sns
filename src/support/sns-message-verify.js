const request = require('request');
const crypto = require('crypto');

const certificateCache = {};
const signatureStringOrder = {
    'Notification'             : ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type'],
    'SubscriptionConfirmation' : ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
    'UnsubscribeConfirmation'  : ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type']
};

module.exports = { verifySignature: verifySignature };

function verifySignature(msg, cb) {
    if (msg.SignatureVersion !== '1') {
        return cb(new Error(`SignatureVersion '${msg.SignatureVersion}' not supported.`));
    }

    downloadCertificate(msg.SigningCertURL, function(error, pem) {
        if (error) return cb(error);

        let signatureString = createSignatureString(msg);

        try {
            let verifier = crypto.createVerify('RSA-SHA1');
            verifier.update(signatureString, 'utf8');
            if (!verifier.verify(pem, msg.Signature, 'base64')) {
                return cb(new Error('Signature verification failed'));
            }
        } catch (error) {
            return cb(new Error(`Signature verification failed: ${error.toString()}`));
        }
        return cb();
    });
}

function downloadCertificate(url, cb) {
    if (typeof url !== 'string') {
        return cb(new Error('Certificate URL not specified'));
    } else if (certificateCache[url]) {
        return cb(null, certificateCache[url]);
    }

    request.get(url, function(err, res, body) {
        if (err) return cb(err);
        certificateCache[url] = body;
        return cb(null, body);
    });
}

function createSignatureString(msg) {
    let chunks = [];
    for(let field of signatureStringOrder[msg.Type]) {
        if (msg[field]) {
            chunks.push(field);
            chunks.push(msg[field]);
        }
    }
    return chunks.join('\n') + '\n';
}
