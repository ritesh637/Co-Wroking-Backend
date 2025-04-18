exports.validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

exports.validatePhone = (phone) => {
  const re = /^[0-9]{10,15}$/;
  return re.test(phone);
};
