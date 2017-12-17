#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import sys
import traceback
import itertools
import time

from ethereum.tools.keys import decode_keystore_json
from joblib import Parallel, delayed
from optparse import OptionParser
from recover_tools import encode_hex, getseed

# Option parsing

parser = argparse.ArgumentParser(description="Pyeth recovery tool.")
parser.add_argument('-p', '--password',
                    default=None, dest='pw',
                    help="A single password to try against the wallet.")
parser.add_argument('-f', '--passwords-file',
                    default=None, dest='pwfile',
                    help="A file containing a newline-delimited list of passwords to try.")
parser.add_argument('-s', '--password-spec-file',
                    default=None, dest='pwsfile',
                    help="A file containing a password specification")
parser.add_argument('-q', '--password-perm-file',
                    default=None, dest='pwqfile',
                    help="A file containing a password permutations specification")
parser.add_argument('-k', '--permutation-max-elements',
                    default=2, dest='k', type=int,
                    help="The maximum elements of permutations set to use to create a password")
parser.add_argument('-w', '--wallet',
                    default='wallet.json', dest='wallet',
                    help="The wallet against which to try the passwords.")
parser.add_argument('-t', '--threads',
                    default=-1, dest='t', type=int,
                    help="Number of threads")
parser.add_argument("-v", "--verbose", action="count", default=0,
                    help="Be more verbose.")


options = parser.parse_args(sys.argv[1:])

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

class PasswordFoundException(Exception):
    pass

def generate_all(el, tr):
    if el:
        for j in range(len(el[0])):
            for w in generate_all(el[1:], tr + el[0][j]):
                yield w
    else:
        yield tr

def attempt(w, pw, verbose):
    print("Attempting password: %s" % pw)
    if not isinstance(pw, str):
        pw = ''.join(str(i) for i in pw)

    if verbose > 0:
        print (pw)

    try:
        if 'encseed' in w:
            seed = getseed(w['encseed'], pw, w['ethaddr'])
        else:
            seed = decode_keystore_json(w, pw)

        if seed:
            print(
                """\n\nYour seed is:\n%s\n\nYour password is:\n%s\n""" %
                (encode_hex(seed), pw))
            raise PasswordFoundException()

    except ValueError:
        return None

def pwds():
    result = []

    if options.pw:
        result.append(options.pw)

    if options.pwfile:
        result.extend(list_passwords())

    if options.pwsfile:
        grammar = eval(open(options.pwsfile, 'r').read())
        result = itertools.chain(result, generate_all(grammar,''))

    if options.pwqfile:
        perms_tuple = eval(open(options.pwqfile, 'r').read())
        result = itertools.chain(
                result,
                itertools.permutations(perms_tuple, options.k))
        total = 1
        for i in range(len(perms_tuple)-options.k, len(perms_tuple)):
            total *= i
        print("Total passwords to try: " + str(total))
        print("Expected days at 500/s: %.5f" % ((((total/500.0)/60)/60)/24))

    return result

def __main__():
    w = tryopen(options.wallet)

    if not w:
        print("Wallet file not found! (-h for help)")
        exit(1)

    if not(options.pw or options.pwfile or options.pwsfile or options.pwqfile):
        print("No passwords specified! (-h for help)")
        exit(1)

    start = time.time()

    try:
        Parallel(n_jobs=options.t)(
                delayed(attempt)(w, pw, options.verbose) for pw in pwds())
        print("None of the passwords worked.")

    except PasswordFoundException as e:
        pass

    except Exception as e:
        traceback.print_exc()
        sys.stdout.write('\a')
        sys.stdout.flush()

    print("elapsed: " + str(time.time()-start))

if __name__ == "__main__":
    __main__()
