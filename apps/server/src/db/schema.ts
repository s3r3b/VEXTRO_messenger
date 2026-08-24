// apps/server/src/db/schema.ts
import { pgTable, index, uniqueIndex, varchar, text, timestamp, uuid, integer } from 'drizzle-orm/pg-core';

// Twój dotychczasowy bufor - zostaje bez zmian
export const offlineMessages = pgTable('offline_messages', {
    id: uuid('id').defaultRandom().primaryKey(),
    messageId: varchar('message_id', { length: 255 }).notNull(),
    conversationId: varchar('conversation_id', { length: 255 }).notNull(),
    recipientId: varchar('recipient_id', { length: 255 }).notNull(),
    senderId: varchar('sender_id', { length: 255 }).notNull(),
    senderDeviceId: varchar('sender_device_id', { length: 255 }).notNull(),
    recipientDeviceId: varchar('recipient_device_id', { length: 255 }).notNull(),
    ciphertext: text('ciphertext').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
    messageIdUnique: uniqueIndex('offline_messages_message_id_idx').on(table.messageId),
    recipientCreatedAtIndex: index('offline_messages_recipient_created_at_idx').on(table.recipientId, table.createdAt),
}));

// 1. REJESTR TOŻSAMOŚCI I KLUCZY ŚREDNIOTERMINOWYCH
export const identities = pgTable('identities', {
    // Ślepy Serwer używa tego tylko jako stringa do routingu. Nie wie, kim jest user.
    userId: varchar('user_id', { length: 255 }).primaryKey(),

    // Identity Key (IK): Publiczny klucz długoterminowy, zrzucany do Base64
    identityKey: text('identity_key').notNull(),

    // Signed Prekey (SPK): Publiczny klucz średnioterminowy (Base64)
    signedPrekey: text('signed_prekey').notNull(),

    // Podpis kryptograficzny SPK wykonany przez Identity Key.
    // Klient Alicji weryfikuje to po pobraniu, upewniając się, że SPK należy do Boba.
    signature: text('signature').notNull(),

    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(), // Będziemy aktualizować przy rotacji SPK
});

// 2. PULA KLUCZY JEDNORAZOWYCH (OPK)
export const oneTimePrekeys = pgTable('one_time_prekeys', {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: varchar('user_id', { length: 255 })
        .notNull()
        .references(() => identities.userId, { onDelete: 'cascade' }),

    // Klient musi wiedzieć, który klucz z jego puli został użyty przez nadawcę
    keyId: integer('key_id').notNull(),

    // Sam jednorazowy klucz publiczny (Base64)
    key: text('key').notNull(),
}, (table) => ({
    userKeyIdUnique: uniqueIndex('one_time_prekeys_user_key_id_idx').on(table.userId, table.keyId),
}));