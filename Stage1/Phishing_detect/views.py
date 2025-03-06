from django.shortcuts import render, redirect
import re

def is_valid_url(url):
    """
    Validate if the input is a proper URL.
    """
    url_pattern = re.compile(
        r"^(https?://)?"  # Optional http:// or https://
        r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})"  # Domain name
        r"(:[0-9]{1,5})?"  # Optional port
        r"(/.*)?$"  # Optional path
    )
    return re.match(url_pattern, url) is not None

def is_phishing_url(url):
    """
    Detect phishing indicators in the given URL.
    """
    phishing_patterns = [
        r"http://",  # URLs without HTTPS
        r"@|%",  # Presence of "@" or "%" symbols
        r"-",  # Hyphen in domain (e.g., http://secure-bank-login.com)
        r"([0-9]{1,3}\.){3}[0-9]{1,3}",  # Presence of IP address in URL
        r"free|login|verify|secure|update|account|bank",  # Common phishing keywords
        r"\.tk|\.ml|\.ga|\.cf|\.gq",  # Suspicious top-level domains
        r"https?://[^\s]*[.][a-z]{2,4}/[^\s]*[.][a-z]{2,4}",  # Double extensions
        r"https?://[^\s]*[.][a-z]{2,4}.*//",  # Double slashes in URL path
    ]

    for pattern in phishing_patterns:
        if re.search(pattern, url.lower()):
            return True
    
    return False

def home(request):
    if request.method == "POST":
        url = request.POST.get("uploadText", "").strip()  # Get input and remove spaces

        if url:  # Ensure input is not empty
            if is_valid_url(url):  # Check if it's a valid URL
                if is_phishing_url(url):
                    request.session["obj"] = "Phishing Detected: " + url  # Store in session
                else:
                    request.session["obj"] = "Legitimate URL: " + url  # Store in session
            else:
                request.session["error"] = "Invalid URL. Please enter a correct URL format."

        return redirect("home")  # Redirect to clear POST data

    # Remove stored session data after displaying once
    obj = request.session.pop("obj", None)
    error = request.session.pop("error", None)

    return render(request, "home.html", {"obj": obj, "error": error})
