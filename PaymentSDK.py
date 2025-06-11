import hashlib
import json
import base64
import requests
import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class PaymentSDK:
    def __init__(self, iv_key, consumer_secret, consumer_key, environment, root_domain):
        self.IVKey = iv_key
        self.consumerSecret = consumer_secret
        self.consumerKey = consumer_key
        self.environment = environment
        self.root_domain = root_domain.lower()

    def get_checkout_base_url(self):
        if self.environment == "production":
            return f"https://api.gateway.{self.root_domain}"
        return f"https://sandbox.api.gateway.{self.root_domain}"

    def get_direct_charge_base_url(self):
        if self.environment == "production":
            return f"https://api.gateway.{self.root_domain}/v1"
        return f"https://sandbox.api.gateway.{self.root_domain}/v1"

    def get_checkout_auth_url(self):
        return f"{self.get_checkout_base_url()}/api/v1/api-auth/access-token"

    def get_direct_charge_auth_url(self):
        return f"{self.get_direct_charge_base_url()}/auth"

    def validate_payload(self, obj):
        required_keys = [
            "msisdn",
            "account_number",
            "country_code",
            "currency_code",
            "client_code",
            "due_date",
            "customer_email",
            "customer_first_name",
            "customer_last_name",
            "merchant_transaction_id",
            "preferred_payment_option_code",
            "callback_url",
            "request_amount",
            "request_description",
            "success_redirect_url",
            "fail_redirect_url",
            "invoice_number",
            "language_code",
            "service_code",
        ]
        for key in required_keys:
            if key not in obj:
                raise Exception(f"Missing required key: {key}")

    def encrypt(self, payload):
        secret_bytes = (
            hashlib.sha256(self.consumerSecret.encode("utf-8"))
            .hexdigest()[:32]
            .encode("utf-8")
        )
        iv_bytes = (
            hashlib.sha256(self.IVKey.encode("utf-8")).hexdigest()[:16].encode("utf-8")
        )

        cipher = AES.new(secret_bytes, AES.MODE_CBC, iv_bytes)
        encrypted_bytes = cipher.encrypt(pad(payload.encode("utf-8"), AES.block_size))

        return base64.b64encode(encrypted_bytes).decode("utf-8")

    async def _access_token_manager(self, api_url, post_data):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            response = requests.post(api_url, data=post_data, headers=headers)
            response_data = response.json()

            access_token = response_data.get("access_token")

            if access_token:
                return access_token
            elif response.status_code == 401:
                error_message = "Invalid Credentials!"
                print(error_message)
                raise Exception(error_message)
            else:
                raise Exception("Access token not found in response")
        except Exception as error:
            print("Error:", str(error))
            raise error

    async def get_access_token(self):
        auth_data = {
            "consumerKey": self.consumerKey,
            "consumerSecret": self.consumerSecret,
        }
        api_url = self.get_checkout_auth_url()
        post_data = self.urlencode_params(auth_data)

        return await self._access_token_manager(api_url, post_data)

    async def get_direct_api_access_token(self):
        auth_data = {
            "consumer_key": self.consumerKey,
            "consumer_secret": self.consumerSecret,
        }

        api_url = self.get_direct_charge_auth_url()
        post_data = self.urlencode_params(auth_data)

        return await self._access_token_manager(api_url, post_data)

    def urlencode_params(self, params):
        return "&".join([f"{key}={value}" for key, value in params.items()])

    async def get_checkout_status(self, merchant_transaction_id, access_token):
        api_url = (
            f"{self.get_checkout_base_url()}/api/v1/checkout/request/status?"
            f"merchant_transaction_id={merchant_transaction_id}"
        )
        headers = {
            "Authorization": f"Bearer {access_token}",
        }

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(api_url, headers=headers) as response:
                if response.status == 404:
                    raise Exception(
                        f"Merchant Transaction ID '{merchant_transaction_id}' not Found"
                    )
                return await response.json()

    async def check_checkout_status(self, merchant_transaction_id):
        try:
            access_token = await self.get_access_token()
            status = await self.get_checkout_status(
                merchant_transaction_id, access_token
            )
            return status
        except Exception as error:
            print(f"Error: {error}")
            raise error

    async def get_charge_request_status(self, charge_request_id):
        try:
            access_token = await self.get_direct_api_access_token()

            url = f"{self.get_direct_charge_base_url()}/transaction/{charge_request_id}/status"

            headers = {
                "x-access-token": access_token,
                "Content-Type": "application/json",
            }

            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        response_data = await response.text()
                        return json.loads(response_data)
                    else:
                        print(
                            "Failed to make GET request. Response code:",
                            response.status,
                        )
                        raise Exception(
                            "Failed to make GET request. Response code: "
                            + str(response.status)
                        )

        except Exception as e:
            print("Failed to make GET request:", str(e))
            raise RuntimeError("Failed to make GET request: " + str(e))

    async def direct_charge(self, payload):
        try:
            url = f"{self.get_direct_charge_base_url()}/mobile-money/charge"

            access_token = await self.get_direct_api_access_token()

            payment_payload = json.loads(payload)

            response = await self.post_request(
                url, self.build_payment_payload(payment_payload), access_token
            )
            return response

        except Exception as error:
            print("Error:", str(error))

    async def post_request(self, url, data, access_token):
        try:
            headers = {
                "x-access-token": access_token,
                "Content-Type": "application/json",
            }
            # Disable SSL verification
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
            # async with aiohttp.ClientSession() as session:

                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 201:
                        result = await self.handle_response(response)
                        return result
                    else:
                        print(
                            "Failed to make POST request. Response code:",
                            response.status,
                        )
                        raise Exception(
                            "Failed to make POST request. Response code: "
                            + str(response.status)
                        )

        except Exception as e:
            print("Failed to make POST request:", str(e))
            raise RuntimeError("Failed to make POST request: " + str(e))

    def build_payment_payload(self, payload):
        common_payload = {
            "external_reference": payload.get("external_reference"),
            "origin_channel_code": "API",
            "originator_msisdn": payload.get("originator_msisdn"),
            "payer_msisdn": payload.get("payer_msisdn"),
            "service_code": payload.get("service_code"),
            "account_number": payload.get("account_number"),
            "client_code": payload.get("client_code"),
            "payer_email": payload.get("payer_email"),
            "country_code": payload.get("country_code"),
            "invoice_number": payload.get("invoice_number"),
            "currency_code": payload.get("currency_code"),
            "amount": payload.get("amount"),
            "add_transaction_charge": payload.get("add_transaction_charge"),
            "transaction_charge": payload.get("transaction_charge"),
            "extra_data": payload.get("extra_data"),
            "description": "Payment by " + payload.get("payer_msisdn"),
            "notify_client": payload.get("notify_client"),
            "notify_originator": payload.get("notify_originator"),
        }

        mpesa_payload = {
            **common_payload,
            "payment_method_code": "MPESA_KEN",
            "paybill": payload.get("paybill"),
        }

        airtel_payload = {
            **common_payload,
            "payment_method_code": "AIRTEL_KEN",
        }

        result_payload = (
            mpesa_payload
            if payload.get("payment_method_code") == "MPESA_KEN"
            else airtel_payload
        )
        return result_payload

    async def handle_response(self, response):
        try:
            response_data = await response.text()
            return json.loads(response_data)
        except Exception as e:
            print("Error processing POST response:", str(e))
            raise RuntimeError("Error processing POST response: " + str(e))
