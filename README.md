pyethrecover
============

This is a tool for those of you who've somehow lost your Ethereum wallet password. It's essentially a stripped-down version of [pyethsaletool](https://github.com/ethereum/pyethsaletool) with the additional feature of being able to read passwords in from a newline-delimited file. This will make guessing your password a lot faster!

This tool requires Python 2. Maybe it will one day be ported to Python 3, but I haven't had a chance to do so yet.

Summary
=======

    Usage: pyethrecover.py [options]
    
    Options:
      -h, --help            show this help message and exit
      -p PW, --password=PW  A single password to try against the wallet.
      -f PWFILE, --passwords-file=PWFILE
                            A file containing a newline-delimited list of
                            passwords to try. (default: pwds.txt)
      -w WALLET, --wallet=WALLET
                            The wallet against which to try the passwords.
                            (default: wallet.json)
    

Example
=======

Let's say you have a wallet file named `ethereum-wallet.json` protected by the password `correct horse battery staple`. You enter your guesses into a file named `passwords.txt`, like so:

    shelly sells seashells down by the seashore
    It was the best time of times, it was the worst of times...
    Password1
    correct horse battery staple
    mean mr mustard sleeps in the park

If you run the utility like so...

    ./pyethrecover.py -w ethereum-wallet.json -f passwords.txt

...you should get back something like this:

    x x x 

    Your seed is:
    abc123abc123...

    Your password is:
    correct horse battery staple

(The three `x`s indicate the three failed passwords before the correct password was found.)
