const cookiesOptions = {
    httpOnly: true,
    secure: false,
    samesite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
}

module.exports = cookiesOptions;