import type { Express } from "express";
import { auth } from "express-openid-connect";
import { appConfig } from "./app";

/**
 * Auth0 Configuration
 * @start by hitting `login` in FE
 * @lotout by hitting `logout`
 */

const config = {
  authRequired: false,
  auth0Logout: true,
  secret: appConfig.AUTH0_SECRET,
  baseURL: `${process.env.AUTH0_BASE_URL}`,
  clientID: `${process.env.AUTH0_CLIENT_ID}`,
  issuerBaseURL: `${process.env.AUTH0_ISSUER_URL}`,
};

export const configure = (app: Express) => {
  app.use(auth(config));
};
