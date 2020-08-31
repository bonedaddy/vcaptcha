# vcaptcha

vcaptcha is a proof of concept alternative to existing captcha systems using verifiable delay functions (vdf) to provide a privacy first, centralized provider free captcha service. It is non-interactive so that the end-user doesn't need to manually solve a puzzle. It in theory should be effective at stopping ddos attacks or bots however this hasn't been tested. Unfortunately at the moment vcaptcha requires golang as there is yet no solver for it in python or javascript.

If you want to support vcaptcha you can send me XMR: `848dhb5aP9jLgnQfdTv3xnArh77xRSgTAWNxhf8U98BMfn4X2MngYi1ScSC2JAo16MPdtQfheojBv12vcrwedjdqKLHEPSw`

# overview

The VDF library used requires that each VDF be given a 32-byte seed along with specifying the difficulty. To get this 32-byte seed we leverage segmentio's KSUID format, which allows us to collect some metadata, such as the time captchas were generated without any personally identifiable information.

This KSUID is bundled into a "ticket" which is really a JSON object containing the KSUID, difficulty, and proof (when ticket is generated the proof doesnt yet exist). Information about the ticket is stored in memory on the server so we can keep track of tickets we have given to clients. We send this information to the client who will then solve the VDF.

After the VDF is solved the proof is then stored inside the ticket, and sent back to the server. The server then verifies that we did give out this seed + difficulty combination before. The proof is verified and if everything checks out we mark the captcha as solved, and generate a JWT which is then used to authenticate the user in the future.

# future improvements

* each captcha can be used by at most one session
  * this prevents attacks in which a solved vdf is used across many users
* enable captcha solve, and current active captcha information persisting to storage or other
  * at the moment it is simply stored in memory
* implement vdf solver in python and javascript


# license

all code in the `vdf` folder is from `from https://github.com/harmony-one/vdf` i have included it in-tree as the harmony-one repository isn't very go modules friendly.