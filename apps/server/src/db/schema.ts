// apps/server/src/db/schema.ts
import { pgTable, varchar, text, timestamp, uuid, integer } from 'drizzle-orm/pg-core';

// Twój dotychczasowy bufor - zostaje bez zmian
export const offlineMessages = pgTable('offline_messages', {
    id: uuid('id').defaultRandom().primaryKey(),
    recipientId: varchar('recipient_id', { length: 255 }).notNull(),
    senderId: varchar('sender_id', { length: 255 }).notNull(),
    ciphertext: text('ciphertext').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
});

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
});