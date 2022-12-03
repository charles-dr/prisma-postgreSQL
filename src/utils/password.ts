import bcrypt from "bcrypt";

export const encryptPassword = (password: string) => {
  return bcrypt.hash(password, 10);
};

export const comparePassword = (plain: string, hashed: string) => {
  return bcrypt.compare(plain, hashed);
};
