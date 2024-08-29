# Etape de build
FROM node:20-alpine AS builder
ARG NODE_ENV=development
ENV NODE_ENV=${NODE_ENV}
WORKDIR /usr/src/app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build





# Étape de production
FROM node:20-alpine AS production

ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /usr/src/app

# Copier les fichiers de dépendances
COPY package.json ./

# Installer uniquement les dépendances de production
RUN npm install --omit=dev


# Copier les fichiers compilés depuis l'étape de développement
COPY --from=builder /usr/src/app/dist ./dist

# Exposer le port sur lequel l'application s'exécute
EXPOSE 3000

# Commande pour exécuter l'application
CMD ["node", "dist/main"]