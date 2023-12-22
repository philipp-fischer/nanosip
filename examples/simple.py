from nanosip import Invite, SIPAuthCreds, call_and_cancel

if __name__ == "__main__":
    auth_creds = SIPAuthCreds(username="58209475user", password="example_password")

    inv = Invite(
        uri_from="sip:58209475user@sipgate.de",
        uri_to="sip:+49810001503@sipgate.de",
        uri_via="sipgate.de",
        auth_creds=auth_creds,
    )

    call_and_cancel(inv, 5)
