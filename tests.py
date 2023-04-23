import os
import random
import unittest
import pprint

from io import StringIO
from contextlib import redirect_stdout

from Cryptodome.Cipher import AES

from tvla_semirandom import AESSemi
from tvla_semirandom import random_hw_normal, random_with_hw, hw
from tvla_semirandom import aes_semi_random_generator


class TestAESSemi(unittest.TestCase):
    n_random_cases = 1

    @staticmethod
    def generate_random_test_case(keysize_bytes=16, hw_tuple=None):
        sio = StringIO()
        key = os.urandom(keysize_bytes)
        plain = os.urandom(16)

        with redirect_stdout(sio):
            cipher = AESSemi(key, print_states=True).encrypt_block(plain)

        sio.seek(0)
        intermediates = sio.readlines()
        randomline = random.choice(intermediates)
        bias_round, bias_operation, bias_state = list(filter(None, randomline.split(' ')))
        bias_round = int(bias_round)

        if hw_tuple:
            hwgen = random_hw_normal(hw_tuple[0], hw_tuple[1], 128)
            bias_state = random_with_hw(next(hwgen), 128)
            cipher = AESSemi(key).partial_encrypt_block(bias_round, bias_operation, bias_state)
            plain = AESSemi(key).decrypt_block(cipher)
            bias_state = bias_state.hex()

        # Store as hex strings for easier pprinting in case of problems
        test_case = {
            'key': key.hex(),
            'plain': plain.hex(),
            'cipher': cipher.hex(),
            'bias_round': bias_round,
            'bias_operation': bias_operation,
            'bias_state': bias_state,
        }

        return test_case
    
    def _run_test_case(self, test_case):
        key = bytes.fromhex(test_case['key'])
        plain = bytes.fromhex(test_case['plain'])
        cipher = bytes.fromhex(test_case['cipher'])

        with self.subTest(part='in/out compare'):
            cipher1 = AESSemi(key).partial_encrypt_block(
                test_case['bias_round'], test_case['bias_operation'], bytes.fromhex(test_case['bias_state']))
            plain1 = AESSemi(key).decrypt_block(cipher)
            cipher2 = AES.new(key, AES.MODE_ECB).encrypt(plain)
            plain2 = AES.new(key, AES.MODE_ECB).decrypt(cipher)

            self.assertEqual(test_case['plain'],  plain1.hex(),  f'PLAIN PROBLEM\n{plain1.hex()=}\n{pprint.pformat(test_case)}')
            self.assertEqual(test_case['plain'],  plain2.hex(),  f'PLAIN PROBLEM\n{plain2.hex()=}\n{pprint.pformat(test_case)}')
            self.assertEqual(test_case['cipher'], cipher1.hex(), f'CIPHER1 PROBLEM\n{cipher1.hex()=}\n{pprint.pformat(test_case)}')
            self.assertEqual(test_case['cipher'], cipher2.hex(), f'CIPHER2 PROBLEM\n{cipher2.hex()=}\n{pprint.pformat(test_case)}')

        with self.subTest(part='internal state compare'):
            sio = StringIO()

            sio.seek(0)
            with redirect_stdout(sio):
                cipher3 = AESSemi(key, print_states=True).encrypt_block(plain)
            sio.seek(0)
            plain_intermediates = sio.readlines()

            sio.seek(0)
            with redirect_stdout(sio):
                plain3 = AESSemi(key, print_states=True).decrypt_block(cipher)
            sio.seek(0)
            cipher_intermediates = sio.readlines()

            for a,b in zip(plain_intermediates, cipher_intermediates[::-1]):
                with self.subTest():
                    self.assertEqual(a[:-1].split(' ')[-1], b[:-1].split(' ')[-1], f'\n{a=}\n{b=}')

    def _test_random_test_case(self, keysize_bytes):
        test_case = TestAESSemi.generate_random_test_case(keysize_bytes)
        self._run_test_case(test_case)
    
    def _test_low_biased_test_case(self, keysize_bytes):
        lower_bound = 0
        upper_bound = 10
        hw_tuple = (lower_bound, upper_bound)
        test_case = TestAESSemi.generate_random_test_case(keysize_bytes, hw_tuple)

        with self.subTest('low hw bias check'):
            # TODO check distribution?
            self.assertGreaterEqual(sum(hw(b) for b in bytes.fromhex(test_case['bias_state'])), lower_bound)
            self.assertLessEqual(sum(hw(b) for b in bytes.fromhex(test_case['bias_state'])), upper_bound)
        
        self._run_test_case(test_case)
    
    def _test_high_biased_test_case(self, keysize_bytes):
        lower_bound = 110
        upper_bound = 128
        hw_tuple = (lower_bound, upper_bound)
        test_case = TestAESSemi.generate_random_test_case(keysize_bytes, hw_tuple)

        self._run_test_case(test_case)

    def test_random_aes128_test_case(self):
        for i in range(self.n_random_cases):
            with self.subTest(i=i):
                with self.subTest(biased=False):
                    self._test_random_test_case(16)
                with self.subTest(biased=True):
                    self._test_low_biased_test_case(16)
                    self._test_high_biased_test_case(16)

    def test_random_aes192_test_case(self):
        for i in range(self.n_random_cases):
            with self.subTest(i=i):
                with self.subTest(biased=False):
                    self._test_random_test_case(24)
                with self.subTest(biased=True):
                    self._test_low_biased_test_case(24)
                    self._test_high_biased_test_case(24)

    def test_random_aes256_test_case(self):
        for i in range(self.n_random_cases):
            with self.subTest(i=i):
                with self.subTest(biased=False):
                    self._test_random_test_case(32)
                with self.subTest(biased=True):
                    self._test_low_biased_test_case(32)
                    self._test_high_biased_test_case(32)

    @unittest.expectedFailure
    def test_invalid_key(self):
        with self.subTest('empty key'):
            AESSemi(b'')
        with self.subTest('wrong sized key'):
            AESSemi(b'0'*200)

class TestSemiRandomGenerator(unittest.TestCase):
    n_random_cases = 1
    # TODO check distribution?

    def test_valid_hw_values(self):
        for i in range(self.n_random_cases):
            with self.subTest(i=i):
                bounds = (random.randint(0, 127), random.randint(0, 127))
                bounds = sorted(bounds)
                if bounds[0] == bounds[1]:
                    bounds[1] += 1

                bias_round = 5
                bias_op = 'mix_columns'

                key = os.urandom(16)
                tvla_generator = aes_semi_random_generator(key, bounds[0], bounds[1], bias_round, bias_op)
                
                (plain, cipher) = next(tvla_generator)

                sio = StringIO()
                with redirect_stdout(sio):
                    AESSemi(key, print_states=True).encrypt_block(plain)
                sio.seek(0)
                intermediates = sio.readlines()

                intermediate_line = next(filter(lambda x: f'{bias_round} {bias_op}' in x, intermediates))
                bias_state = intermediate_line.strip().split(' ')[-1]
                bias_state = bytes.fromhex(bias_state)

                self.assertGreaterEqual(sum(hw(b) for b in bias_state), bounds[0], f'\n{key.hex()=}\n{bias_round=}\n{bias_op=}\n{bias_state=}')
                self.assertLessEqual(sum(hw(b) for b in bias_state), bounds[1], f'\n{key.hex()=}\n{bias_round=}\n{bias_op=}\n{bias_state=}')

    @unittest.expectedFailure
    def test_invalid_settings(self):
        key = os.urandom(16)
        bias_round = 0
        bias_op = 'mix_columns'
        min_hw = 0
        max_hw = 8

        with self.subTest(key=key.hex(), bias_round=bias_round, bias_op=bias_op, min_hw=min_hw, max_hw=max_hw):
            next(aes_semi_random_generator(key, min_hw, max_hw, bias_round, bias_op))

        key = os.urandom(16)
        bias_round = 22
        bias_op = 'mix_columns'
        min_hw = 0
        max_hw = 8

        with self.subTest(key=key.hex(), bias_round=bias_round, bias_op=bias_op, min_hw=min_hw, max_hw=max_hw):
            next(aes_semi_random_generator(key, min_hw, max_hw, bias_round, bias_op))

        key = os.urandom(24)
        bias_round = 5
        bias_op = 'sub_bytes'
        min_hw = -1
        max_hw = 8

        with self.subTest(key=key.hex(), bias_round=bias_round, bias_op=bias_op, min_hw=min_hw, max_hw=max_hw):
            next(aes_semi_random_generator(key, min_hw, max_hw, bias_round, bias_op))

        key = os.urandom(24)
        bias_round = 10
        bias_op = 'mix_columns'
        min_hw = 0
        max_hw = 200

        with self.subTest(key=key.hex(), bias_round=bias_round, bias_op=bias_op, min_hw=min_hw, max_hw=max_hw):
            next(aes_semi_random_generator(key, min_hw, max_hw, bias_round, bias_op))

if __name__ == "__main__":
    unittest.main()