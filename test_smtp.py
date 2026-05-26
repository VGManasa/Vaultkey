import smtplib

EMAIL = "vaultkey.secure@gmail.com"
APP_PASSWORD = "sfpz hzkh lryw xzld"

try:
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.set_debuglevel(1)   # shows full SMTP logs
    server.starttls()

    server.login(EMAIL, APP_PASSWORD)

    print("LOGIN SUCCESS ✅")

    server.quit()

except Exception as e:
    print("ERROR ❌")
    print(e)