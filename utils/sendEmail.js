const nodemailer = require("nodemailer");

const sendEmail = async (email, subject, url) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const message = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: subject,
    html: `<h3>Click to verify:</h3><a href="${url}">${url}</a>`,
  };

  await transporter.sendMail(message);
};

module.exports = sendEmail;
