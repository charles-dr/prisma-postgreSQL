# Express-Prisma-Passport App

This is a try-feature project with the followings tech stacks.

- Typescript
- [Express.js](https://expressjs.com/)
- [PostgreSQL](https://www.postgresql.org/)
- [Prisma](https://www.prisma.io/)
- [Passport](https://www.passportjs.org/)

## Package Commands

### Run in Development Mode

```bash
yarn development
```

### Prisma Migrate

```bash
yarn prisma:migrate
```

You will be requested to input the migration name.

This needs to be run everytime you change the prisma schema.

### Prisma Client Generation

```bash
yarn prisma:gen
```

This needs to be run whenever you change the package installation.
