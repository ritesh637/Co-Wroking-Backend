
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);

  let statusCode = err.statusCode || res.statusCode || 500;

  if (err.name === "ValidationError") {
    statusCode = 400;
  } else if (err.name === "CastError" && err.kind === "ObjectId") {
    statusCode = 404;
  } else if (err.name === "UnauthorizedError") {
    statusCode = 401;
  } else if (err.code === 11000) {
    statusCode = 400;
  }

  let message = err.message || "Internal Server Error";

  if (err.name === "ValidationError") {
    const errors = Object.values(err.errors).map((el) => el.message);
    message = `Invalid input data: ${errors.join(", ")}`;
  } else if (err.name === "CastError" && err.kind === "ObjectId") {
    message = "Resource not found";
  } else if (err.code === 11000) {
    message = "Duplicate field value entered";
  }

  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
  });
};

module.exports = errorHandler;
