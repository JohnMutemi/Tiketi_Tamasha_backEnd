# Tiketi Tamasha Backend

## Overview

The backend for the Tiketi Tamasha project is built using Flask and SQLAlchemy. It includes functionalities for user management, event handling, ticketing, payment processing, and more. This project also integrates email-based OTP generation and sending.

## Features

- _User Management_: Create, update, and delete users with roles (admin, event organiser, customer).
- _Event Management_: Create and manage events, including assigning categories.
- _Ticketing_: Issue and manage tickets for events.
- _Payment Processing_: Handle payments and record payment details.
- _OTP Generation_: Generate and send OTPs for user verification.

## Clone the Repository

git clone git@github.com:JohnMutemi/Tiketi_Tamasha_backEnd.git
cd Tiketi_Tamasha_backEnd

## Email Configuration

The OTP functionality uses SMTP to send emails. Update the email configuration in send_otp_to_email function with your SMTP server details:

- _SMTP Server_: smtp.gmail.com
- _SMTP Port_: 587
- _SMTP Username_: tiketitamasha@gmail.com
- _SMTP Password_: <your-smtp-password>

## Code Description

### Models

- _User_: Represents users in the system with attributes for authentication, roles, and relationships with events and tickets.
- _Event_: Represents events with details such as title, description, location, and related tickets and categories.
- _Ticket_: Represents tickets purchased for events, including details like price and status.
- _Payment_: Represents payments made for tickets, including payment method and status.
- _Category_: Represents categories for organizing events.
- _EventCategory_: Association table linking events and categories.
- _RevokedToken_: Represents revoked JWT tokens.
- _BookedEvent_: Represents booked events with details and ticket types.

### OTP Generation and Email

- _generate_otp()_: Generates a 6-digit OTP.
- _send_otp_to_email(user_email, otp_code)_: Sends an OTP to the specified email address using SMTP.

## To Contribute

1. _Fork the Repository_
2. _Create a New Branch_
3. _Commit Your Changes_
4. _Push to the Branch_
5. _Open a Pull Request_
