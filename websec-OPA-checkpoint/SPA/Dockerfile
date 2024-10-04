# Use a Node.js base image
FROM node:18

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (if available) into the container
COPY package*.json ./

# Install dependencies
RUN npm install

COPY . . 

# Expose port 3000 for the container
EXPOSE 3000

# Run the SPA
CMD ["npm", "run", "start"]