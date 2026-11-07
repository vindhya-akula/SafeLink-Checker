
import base64
import httpx

from app.config import settings


VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def check_virustotal(url: str):

    api_key = settings.VIRUSTOTAL_API_KEY

    if not api_key:
        return {
            "status": "not_configured",
            "message": "VirusTotal API key is not configured."
        }

    headers = {
        "x-apikey": api_key
    }

    # Encode URL to create VirusTotal URL identifier
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    async with httpx.AsyncClient(timeout=20.0) as client:

        try:

            # Step 1: Retrieve existing URL report
            response = await client.get(
                f"{VT_BASE_URL}/urls/{url_id}",
                headers=headers
            )

            if response.status_code == 200:

                data = response.json()

                attributes = data.get(
                    "data", {}
                ).get("attributes", {})

                stats = attributes.get(
                    "last_analysis_stats", {}
                )

                return {
                    "status": "completed",
                    "source": "VirusTotal",
                    "statistics": stats,
                    "reputation": attributes.get("reputation", 0)
                }

            # Step 2: Submit URL if no report exists
            if response.status_code == 404:

                response = await client.post(
                    f"{VT_BASE_URL}/urls",
                    headers=headers,
                    data={"url": url}
                )

                if response.status_code == 200:

                    data = response.json()

                    return {
                        "status": "queued",
                        "analysis_id": data["data"]["id"],
                        "message": "URL submitted for analysis."
                    }

            if response.status_code == 401:
                return {
                    "status": "authentication_error",
                    "message": "Invalid VirusTotal API key."
                }

            if response.status_code == 403:
                return {
                    "status": "access_denied",
                    "message": "VirusTotal API access is restricted."
                }

            if response.status_code == 429:
                return {
                    "status": "rate_limited",
                    "message": "VirusTotal API rate limit reached."
                }

            return {
                "status": "api_error",
                "message": f"VirusTotal returned HTTP {response.status_code}."
            }

        except httpx.TimeoutException:

            return {
                "status": "timeout",
                "message": "VirusTotal request timed out."
            }

        except httpx.RequestError:

            return {
                "status": "connection_error",
                "message": "Could not connect to VirusTotal."
            }
