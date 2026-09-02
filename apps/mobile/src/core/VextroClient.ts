import {
    type AuthChallengeEvent,
    type ClientMessage,
    type EncryptedMessageEnvelope,
    type ErrorEvent,
    type ServerMessage,
    type SystemEvent,
    PROTOCOL_VERSION,
    vault,
} from '@vextro/crypto';
import { parseServerMessage } from '../../../../packages/crypto/src/ProtocolValidation';
import { parseJsonMessage } from '../../../../packages/crypto/src/ProtocolValidation';
import { mobileMessageStore, mobileStorageAdapter } from './MobileStorageAdapter';

type MessageListener = (envelope: EncryptedMessageEnvelope) => void;
type ErrorListener = (error: Error) => void;

const DEVICE_ID_KEY = 'vextro.device-id';
const MAX_RECONNECT_DELAY_MS = 30_000;
const RETRY_DELAY_MS = 5_000;

function createId(prefix: string): string {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function asError(value: unknown): Error {
    return value instanceof Error ? value : new Error(String(value));
}

export class VextroClient {
    private socket: WebSocket | null = null;
    private accountId: string | null = null;
    private deviceId: string | null = null;
    private serverUrl: string | null = null;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private reconnectDelayMs = 1_000;
    private connectPromise: Promise<void> | null = null;
    private authenticated = false;
    private registrationPending = false;
    private registrationResolve: (() => void) | null = null;
    private registrationReject: ((error: Error) => void) | null = null;
    private messageListener: MessageListener | null = null;
    private errorListener: ErrorListener | null = null;

    setOnMessageListener(listener: MessageListener): void {
        this.messageListener = listener;
    }

    setOnErrorListener(listener: ErrorListener): void {
        this.errorListener = listener;
    }

    async init(accountId: string, serverUrl: string): Promise<void> {
        if (!accountId || !serverUrl) throw new Error('accountId i serverUrl sa wymagane');

        this.accountId = accountId;
        this.serverUrl = this.normalizeServerUrl(serverUrl);
        this.deviceId = await this.getOrCreateDeviceId();
        await vault.init(mobileStorageAdapter);
        await this.connect();
    }

    async sendEnvelope(envelope: EncryptedMessageEnvelope): Promise<void> {
        this.requireIdentity();
        if (envelope.sender.accountId !== this.accountId || envelope.sender.deviceId !== this.deviceId) {
            throw new Error('Koperta nie nalezy do aktywnego urzadzenia');
        }

        await mobileMessageStore.enqueue('outbox', envelope);
        await this.flushOutbox();
    }

    async sendText(): Promise<void> {
        throw new Error('Wysylanie tekstu wymaga skonfigurowanego backendu Rust/libsodium E2EE');
    }

    async flushOutbox(): Promise<void> {
        if (!this.isSocketOpen() || !this.authenticated) return;

        const pending = await mobileMessageStore.listReady('outbox');
        for (const record of pending) {
            if (!this.isSocketOpen()) return;
            await mobileMessageStore.markAttempt('outbox', record.envelope.messageId, RETRY_DELAY_MS);
            this.socket?.send(JSON.stringify(record.envelope));
        }
    }

    disconnect(): void {
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
        this.authenticated = false;
        this.socket?.close();
        this.socket = null;
    }

    private async connect(): Promise<void> {
        if (this.connectPromise) return this.connectPromise;
        if (!this.serverUrl) throw new Error('Klient nie zostal skonfigurowany');

        this.connectPromise = new Promise<void>((resolve, reject) => {
            const socket = new WebSocket(this.serverUrl!);
            this.socket = socket;
            let settled = false;

            socket.onopen = () => {
                this.reconnectDelayMs = 1_000;
                this.send({
                    protocolVersion: PROTOCOL_VERSION,
                    type: 'auth_challenge',
                    accountId: this.accountId!,
                    deviceId: this.deviceId!,
                });
            };

            socket.onmessage = (event) => {
                try {
                    const message = parseJsonMessage(String(event.data), parseServerMessage);
                    void this.handleServerMessage(message, resolve, reject, () => { settled = true; });
                } catch (error) {
                    this.reportError(asError(error));
                    if (!settled) {
                        settled = true;
                        reject(asError(error));
                    }
                }
            };

            socket.onerror = () => {
                const error = new Error('Blad polaczenia WebSocket');
                this.reportError(error);
                if (!settled) {
                    settled = true;
                    reject(error);
                }
            };

            socket.onclose = () => {
                this.authenticated = false;
                this.socket = null;
                if (!settled) {
                    settled = true;
                    reject(new Error('Polaczenie WebSocket zostalo zamkniete'));
                }
                this.scheduleReconnect();
            };
        }).finally(() => {
            this.connectPromise = null;
        });

        return this.connectPromise;
    }

    private async handleServerMessage(
        message: ServerMessage,
        resolve: () => void,
        reject: (error: Error) => void,
        markSettled: () => void,
    ): Promise<void> {
        if (message.type === 'auth_challenge') {
            await this.answerAuthChallenge(message);
            return;
        }

        if (message.type === 'system') {
            await this.handleSystemMessage(message);
            if (message.status === 'authenticated') {
                markSettled();
                resolve();
            }
            return;
        }

        if (message.type === 'error') {
            await this.handleErrorMessage(message);
            if (message.code === 'UNKNOWN_ACCOUNT' && !this.registrationPending) {
                this.registrationPending = true;
                await this.registerNewAccount();
                markSettled();
                resolve();
            } else if (!this.authenticated) {
                markSettled();
                reject(new Error(message.message));
            }
            return;
        }

        if (message.type === 'message') {
            await this.handleIncomingMessage(message);
            return;
        }

        if (message.type === 'message_ack') {
            await this.handleMessageAck(message.messageId, message.status);
            return;
        }

        if (message.type === 'bundle_response') return;
    }

    private async answerAuthChallenge(challenge: AuthChallengeEvent): Promise<void> {
        this.requireIdentity();
        const signature = await vault.signAuthChallenge(this.accountId!, this.deviceId!, challenge.challenge);
        this.send({
            protocolVersion: PROTOCOL_VERSION,
            type: 'auth',
            accountId: this.accountId!,
            deviceId: this.deviceId!,
            identityKey: await vault.getIdentityPublicKey(),
            challenge: challenge.challenge,
            signature,
        });
    }

    private async registerNewAccount(): Promise<void> {
        this.requireIdentity();
        const bundle = await vault.generatePrekeyBundle();
        this.send({
            protocolVersion: PROTOCOL_VERSION,
            type: 'register_bundle',
            accountId: this.accountId!,
            deviceId: this.deviceId!,
            bundle,
        });
        await this.waitForRegistrationConfirmation();
    }

    private async waitForRegistrationConfirmation(): Promise<void> {
        await new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.registrationResolve = null;
                this.registrationReject = null;
                reject(new Error('Timeout rejestracji bundle'));
            }, 10_000);
            this.registrationResolve = () => {
                clearTimeout(timeout);
                this.registrationResolve = null;
                this.registrationReject = null;
                this.authenticated = true;
                this.registrationPending = false;
                resolve();
            };
            this.registrationReject = (error) => {
                clearTimeout(timeout);
                this.registrationResolve = null;
                this.registrationReject = null;
                reject(error);
            };
        });
    }

    private async handleSystemMessage(message: SystemEvent): Promise<void> {
        if (message.status === 'authenticated') {
            this.authenticated = true;
            await this.flushOutbox();
        } else if (message.status === 'bundle_registered') {
            this.registrationResolve?.();
        }
    }

    private async handleErrorMessage(message: ErrorEvent): Promise<void> {
        this.reportError(new Error(`${message.code}: ${message.message}`));
        if (this.registrationPending && message.code !== 'UNKNOWN_ACCOUNT') {
            this.registrationReject?.(new Error(message.message));
        }
    }

    private async handleIncomingMessage(envelope: EncryptedMessageEnvelope): Promise<void> {
        const existing = await mobileMessageStore.get('inbox', envelope.messageId);
        await mobileMessageStore.enqueue('inbox', envelope);
        if (!existing) this.messageListener?.(envelope);

        this.send({
            protocolVersion: PROTOCOL_VERSION,
            type: 'message_ack',
            messageId: envelope.messageId,
            status: 'delivered',
        });
    }

    private async handleMessageAck(messageId: string, status: 'accepted' | 'delivered'): Promise<void> {
        await mobileMessageStore.transition('outbox', messageId, status);
        if (status === 'delivered') await mobileMessageStore.remove('outbox', messageId);
    }

    private send(message: ClientMessage): void {
        if (!this.isSocketOpen()) throw new Error('WebSocket nie jest polaczony');
        const socket = this.socket;
        if (!socket) throw new Error('WebSocket nie jest polaczony');
        socket.send(JSON.stringify(message));
    }

    private isSocketOpen(): boolean {
        return this.socket?.readyState === 1;
    }

    private requireIdentity(): void {
        if (!this.accountId || !this.deviceId) throw new Error('Brak tozsamosci klienta');
    }

    private async getOrCreateDeviceId(): Promise<string> {
        const existing = await mobileStorageAdapter.getItem(DEVICE_ID_KEY);
        if (existing) return existing;
        const deviceId = createId('device');
        await mobileStorageAdapter.setItem(DEVICE_ID_KEY, deviceId);
        return deviceId;
    }

    private normalizeServerUrl(serverUrl: string): string {
        if (serverUrl.startsWith('ws://') || serverUrl.startsWith('wss://')) return `${serverUrl.replace(/\/$/, '')}/ws`;
        return `ws://${serverUrl.replace(/\/$/, '')}/ws`;
    }

    private scheduleReconnect(): void {
        if (!this.serverUrl || this.reconnectTimer) return;
        const delay = this.reconnectDelayMs;
        this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, MAX_RECONNECT_DELAY_MS);
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            void this.connect().catch((error: unknown) => this.reportError(asError(error)));
        }, delay);
    }

    private reportError(error: Error): void {
        this.errorListener?.(error);
    }
}

export const clientEngine = new VextroClient();