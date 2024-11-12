import { Request, Response, NextFunction } from "express";
import AppError from "../utils/AppError";

const sendErrorDev = (err: AppError, res: Response) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  });
};

const sendErrorProd = (err: AppError, res: Response) => {
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  } else {
    console.error("Error!", err);
    res.status(500).json({
      status: "error",
      message: "Something went wrong!",
    });
  }
};

const handleDuplicationErrorDB = (err: any) => {
  if (err.code === "P2002" && err.meta.target.includes("email")) {
    return new AppError("Account with that email already exists", 400);
  }
};

const handleJWTError = () =>
  new AppError(`Invalid token. Please log in again!`, 401);

const handleExpiredTokenError = () =>
  new AppError(`Token expired. Please log in again`, 401);

const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  err.statusCode ||= 500;
  err.status ||= "error";

  if (process.env.NODE_ENV === "development") {
    sendErrorDev(err, res);
  } else {
    if (err.code === "P2002") err = handleDuplicationErrorDB(err);
    if (err.name === "JsonWebTokenError") err = handleJWTError();
    if (err.name === "TokenExpiredError") err = handleExpiredTokenError();
    sendErrorProd(err, res);
  }
};

export default errorHandler;
