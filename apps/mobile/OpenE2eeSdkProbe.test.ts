import { runOpenE2eeRoundTripProbe } from './src/core/OpenE2eeSdkProbe';

runOpenE2eeRoundTripProbe()
    .then((content) => {
        if (content !== 'probe-message') throw new Error(`Unexpected decrypted content: ${content}`);
        console.log('OpenE2EE SDK round-trip probe passed');
    })
    .catch((error: unknown) => {
        console.error(error);
        process.exitCode = 1;
    });