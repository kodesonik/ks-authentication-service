# Étape de construction pour le développement
FROM node:20 AS development

# Définir le répertoire de travail dans le conteneur
WORKDIR /usr/src/app

# Copier les fichiers de dépendances
COPY package*.json ./
COPY eslint* ./
COPY tsconfig* ./
COPY nest-cli.json ./

# Installer les dépendances, y compris les dépendances de développement
RUN npm install

# Copier le reste des fichiers de l'application
# COPY . ./

# Compiler l'application TypeScript en JavaScript
CMD ["npm", "run", "start:dev" ]

