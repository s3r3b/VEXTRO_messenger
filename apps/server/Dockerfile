# Etap 1: Budowanie aplikacji
FROM node:20-alpine AS builder

# Ustawienie katalogu roboczego w kontenerze
WORKDIR /usr/src/app

# Kopiowanie plików package.json i instalacja wszystkich zależności (w tym devDependencies)
# Zakładam, że pliki package*.json znajdują się w katalogu apps/server
COPY package*.json ./
RUN npm install

# Kopiowanie reszty kodu źródłowego
COPY . .

# Budowanie aplikacji (kompilacja TypeScript do JavaScript)
# Zakładam, że w package.json masz skrypt "build"
RUN npm run build

# Etap 2: Tworzenie finalnego, produkcyjnego obrazu
FROM node:20-alpine
WORKDIR /usr/src/app

# Kopiowanie plików package.json i instalacja tylko zależności produkcyjnych
COPY package*.json ./
RUN npm install --omit=dev

# Kopiowanie skompilowanej aplikacji z etapu "builder"
COPY --from=builder /usr/src/app/dist ./dist

# Ujawnienie portu, na którym działa serwer
EXPOSE 3001

# Polecenie uruchamiające serwer
CMD [ "node", "dist/server.js" ]