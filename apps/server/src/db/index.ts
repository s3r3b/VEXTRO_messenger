import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';
import dotenv from 'dotenv';
import path from 'path';

// Ładujemy env z katalogu apps/server
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
    throw new Error('❌ BŁĄD: Brak DATABASE_URL w pliku .env!');
}

// Ustawiamy połączenie. Dla Supabase używamy puli połączeń.
const client = postgres(connectionString, { prepare: false });
export const db = drizzle(client, { schema });