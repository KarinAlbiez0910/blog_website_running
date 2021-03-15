import smtplib

my_email = 'myalbiez@gmail.com'
my_password = 'KarineProg1'
recipient = 'kalbiez@yahoo.com'
name = "Maier"
email = "Maier@gmx.com"
phone = "123"
message = "Hi"
text = f"{name} with the email {email} and phone number {phone} has sent you the following message: {message}"

with smtplib.SMTP(host='smtp.gmail.com') as connection:
    connection.starttls()
    connection.login(password=my_password, user=my_email)
    connection.sendmail(from_addr=my_email,
                        to_addrs=recipient,
                        msg=f'Subject: New person got in contact\n\n{text}')
