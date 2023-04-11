import os
import random

from io import StringIO
from contextlib import redirect_stdout

from Cryptodome.Cipher import AES

from tvla_semirandom import AESSemi
from tvla_semirandom import random_hw_normal, random_with_hw
from tvla_semirandom import aes_semi_random_generator

VERBOSE = 1
import logging
logger = logging.getLogger(__name__)
logging.basicConfig()
logger.setLevel(logging.WARNING - VERBOSE*10)

def generate_random_test_case(keysize=16):
    sio = StringIO()
    key = os.urandom(keysize)
    plain = os.urandom(16)
    with redirect_stdout(sio):
        ciph = AESSemi(key, print_states=True).encrypt_block(plain)
    intermediates = sio.getvalue()
    logger.debug(intermediates)
    randomline = random.choice(intermediates.strip().split('\n'))
    bias_round, bias_operation, bias_state = list(filter(None, randomline.split(' ')))
    test_case = (key, plain, ciph, int(bias_round), bias_operation, bytes.fromhex(bias_state))
    return test_case

def generate_bias_test_case(min_hw=0, max_hw=8, keysize=16):
    sio = StringIO()
    key = os.urandom(keysize)
    plain = os.urandom(16)
    with redirect_stdout(sio):
        ciph = AESSemi(key, print_states=True).encrypt_block(plain)
    intermediates = sio.getvalue()
    logger.debug(intermediates)
    randomline = random.choice(intermediates.strip().split('\n'))
    bias_round, bias_operation, _ = list(filter(None, randomline.split(' ')))
    plain, ciph = next(aes_semi_random_generator(key, min_hw, max_hw, int(bias_round), bias_operation))
    logger.debug(f'{plain.hex()=}')
    logger.debug(f'{ciph.hex()=}')

    test_case = (key, plain, ciph, int(bias_round), bias_operation)
    return test_case

def test_random_test_case(key, plain1, ciph1, bias_round, bias_operation, bias_state):
    logger.debug(f'{bias_round:3d} {bias_operation:15s} {bias_state.hex()}')
    ciph2 = AESSemi(key).partial_encrypt_block(bias_round, bias_operation, bias_state)
    plain2 = AESSemi(key).decrypt_block(ciph2)
    ciph3 = AES.new(key, AES.MODE_ECB).encrypt(plain1)
    assert plain1 == plain2, f'PLAIN PROBLEM \n{plain1.hex()}\n{plain2.hex()}'
    assert ciph1 == ciph2 == ciph3, f'CIPHER PROBLEM \n{ciph1.hex()}\n{ciph2.hex()}\n{ciph3.hex()}'

def test_bias_test_case(key, plain1, ciph1, bias_round, bias_operation):
    logger.debug(f'{bias_round:3d} {bias_operation:15s}')
    ciph3 = AES.new(key, AES.MODE_ECB).encrypt(plain1)
    assert ciph1 == ciph3, f'CIPHER PROBLEM \n{ciph1.hex()}\n{ciph3.hex()}'
 
for x in range(1000):
    logger.debug(f'start of test case {x}')
    test_random_test_case(*generate_random_test_case(16))
    logger.debug(f'end of test case {x}')
logger.info('all random AES-128 test pass')

for x in range(1000):
    logger.debug(f'start of test case {x}')
    test_random_test_case(*generate_random_test_case(24))
    logger.debug(f'end of test case {x}')
logger.info('all random AES-192 test pass')

for x in range(1000):
    logger.debug(f'start of test case {x}')
    test_random_test_case(*generate_random_test_case(32))
    logger.debug(f'end of test case {x}')
logger.info('all random AES-256 test pass')

for x in range(1000):
    logger.debug(f'start of test case {x}')
    test_bias_test_case(*generate_bias_test_case(0, 8, 16))
    test_bias_test_case(*generate_bias_test_case(120, 128, 16))
    logger.debug(f'end of test case {x}')
logger.info('all biased AES-128 test pass')

for x in range(1000):
    logger.debug(f'start of test case {x}')
    test_bias_test_case(*generate_bias_test_case(0, 8, 24))
    test_bias_test_case(*generate_bias_test_case(120, 128, 24))
    logger.debug(f'end of test case {x}')
logger.info('all biased AES-192 test pass')

for x in range(1000):
    logger.debug(f'start of test case {x}')
    test_bias_test_case(*generate_bias_test_case(0, 8, 32))
    test_bias_test_case(*generate_bias_test_case(120, 128, 32))
    logger.debug(f'end of test case {x}')
logger.info('all biased AES-256 test pass')
