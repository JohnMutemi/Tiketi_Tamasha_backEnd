import requests
from flask import current_app

class IntaSend:
    def __init__(self):
        self.public_key = current_app.config['ISPubKey_live_bdabab19-cd29-4975-96dd-87f04c49edb9']
        self.private_key = current_app.config['ISSecretKey_live_afef65ff-656c-446b-b2a3-e7f50a57088d']
        self.base_url = "https://api.intasend.com"

    def initiate_payment(self, amount, phone_number, callback_url):
        url = f"{self.base_url}/mpesa/stk-push"
        headers = {
            "Authorization": f"Bearer {self.private_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "public_key": self.public_key,
            "amount": amount,
            "phone_number": phone_number,
            "callback_url": callback_url,
            "currency": "KES",
            "description": "Payment for ticket"
        }

        response = requests.post(url, json=payload, headers=headers)
        return response.json()

    def verify_payment(self, payment_id):
        url = f"{self.base_url}/payments/verify/{payment_id}"
        headers = {
            "Authorization": f"Bearer {self.private_key}",
        }
        response = requests.get(url, headers=headers)
        return response.json()

    def initiate_stk_push(self, amount, phone_number, callback_url):
        url = f"{self.base_url}/mpesa/stk-push/"
        headers = {
            "Authorization": f"Bearer {self.private_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "public_key": self.public_key,
            "amount": amount,
            "phone_number": phone_number,
            "callback_url": callback_url,
            "currency": "KES",
            "description": "Payment for ticket"
        }

        response = requests.post(url, json=payload, headers=headers)
        return response.json()
