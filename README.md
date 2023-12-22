<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>


<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/philipp-fischer/nanosip">
    <img src="https://raw.githubusercontent.com/philipp-fischer/nanosip/main/images/logo.png" alt="Logo" width="128" height="128">
  </a>

<h3 align="center">nanosip</h3>
  <p align="center">
    Simply ring a phone
    <br />
    <a href="https://github.com/philipp-fischer/nanosip/issues">Report Bug</a>
    ·
    <a href="https://github.com/philipp-fischer/nanosip">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>



## About The Project

nanosip is a minimal implementation of the the [SIP](https://datatracker.ietf.org/doc/html/rfc3261) `INVITE` transaction, which is used to ring another phone.

It is 

- **not** a complete or compliant implementation of SIP.
- **not** establishing a VoIP / audio link with the callee.

Simply rings and hangs up.

This package was created to be used by my home assistant integration "sipcall", however it can be used in any other project.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


## Installation


Install the package from PyPI
```sh
pip install nanosip
```
This package does not have any dependencies

<p align="right">(<a href="#readme-top">back to top</a>)</p>


## Usage

To make a call, you will need

- either a cloud-based SIP registrar (e.g. [sipgate](https://www.sipgate.de/), [easybell](https://www.easybell.de/) or others)
- or a local PBX that runs on your router or local server (e.g. a [FRITZ!Box](https://avm.de/service/wissensdatenbank/dok/FRITZ-Box-7590/42_IP-Telefon-an-FRITZ-Box-anmelden-und-einrichten/) or [asterisk](https://www.asterisk.org/))

From your registrar you will obtain the following required information:

- username
- password
- SIP server
- Domain (usually the same as the server)

You can then make a call like this:

```python
from nanosip import call_and_cancel


auth_creds = SIPAuthCreds(
    username="USERNAME",
    password="PASSWORD"
)

inv = Invite(
    uri_from="sip:USERNAME@DOMAIN",
    uri_to="sip:CALLEE@DOMAIN",
    uri_via="SIP_SERVER",
    auth_creds=auth_creds,
)

call_and_cancel(inv, 15)
```

This package also supports use with `asyncio`. For more examples, check out the `examples/` subfolder.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


## License

Distributed under the GPLv3 License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

