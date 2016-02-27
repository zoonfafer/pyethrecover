#!/usr/bin/env python
from __future__ import print_function
import os
import sys
import json
import getpass
from recover_tools import getseed, pbkdf2, DecryptionException
import traceback
from joblib import Parallel, delayed
import itertools

from optparse import OptionParser

# Option parsing

parser = OptionParser()
parser.add_option('-p', '--password',
                  default=None, dest='pw',
                  help="A single password to try against the wallet.")
parser.add_option('-f', '--passwords-file',
                  default=None, dest='pwfile',
                  help="A file containing a newline-delimited list of passwords to try. (default: %default)")
parser.add_option('-s', '--password-spec-file',
                  default=None, dest='pwsfile',
                  help="A file containing a password specification")
parser.add_option('-w', '--wallet',
                  default='wallet.json', dest='wallet',
                  help="The wallet against which to try the passwords. (default: %default)")

(options, args) = parser.parse_args()

def tryopen(f):
    try:
        assert f
        t = open(f).read()
        try:
            return json.loads(t)
        except:
            raise Exception("Corrupted file: "+f)
    except:
        return None

def list_passwords():
    if not options.pwfile:
        return []
    with open(options.pwfile) as f:
        return f.read().splitlines()


def ask_for_password():
    return getpass.getpass()


class PasswordFoundException(Exception):
    pass

def crack(wallet_filename, grammar):
    with file(wallet_filename, 'r') as f:
        t = f.read()
    w = json.loads(t)
    try:
        Parallel(n_jobs=-1)(delayed(attempt)(w, pw) for pw in generate_all(grammar,''))
    except Exception, e:
        traceback.print_exc()
        while True:
            sys.stdout.write('\a')
            sys.stdout.flush()

def generate_all(el, tr):
    if el:
        for j in xrange(len(el[0])):
            for w in generate_all(el[1:], tr + el[0][j]):
                yield w
    else:
        yield tr

def attempt(w, pw):
    if len(pw) < 10:
        return ""
    try:
        print (pw)
        raise PasswordFoundException(
            """\n\nYour seed is:\n%s\nYour password is:\n%s""" % (getseed(w['encseed'], pbkdf2(pw), w['ethaddr']), pw))

    except DecryptionException as e:
        # print(e)
        return ""

def __main__():
    w = tryopen(options.wallet)
    if not w:
        print("Wallet file not found! (-h for help)")
        exit(1)

    pwds = []

    if not(options.pw or options.pwfile or options.pwsfile):
        print("No passwords specified! (-h for help)")

    if options.pw:
        pwds.append(options.pw)

    if options.pwfile:
        try:
            pwds.extend(list_passwords())
        except:
            print("Password file not found! (-h for help)")
            exit(1)

    if options.pwsfile:
        grammar = eval(file(options.pwsfile, 'r').read())
        pwds = itertools.chain(pwds, generate_all(grammar,''))

    try:
        Parallel(n_jobs=-1)(delayed(attempt)(w, pw) for pw in pwds)
    except Exception, e:
        traceback.print_exc()
        while True:
            sys.stdout.write('\a')
            sys.stdout.flush()

if __name__ == "__main__":
    __main__()
