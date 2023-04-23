import random

from scipy.stats import truncnorm
from numpy import sqrt

from .aes import AESSemi

# Lazy HW calculation
def hw(b):
    return f'{b:08b}'.count('1')

# Lazy random generator given a HW and amount of bits
def random_with_hw(hw, total_bits):
    assert total_bits > 0
    assert total_bits % 8 == 0
    assert total_bits >= hw
    bits = ['1'] * hw + ['0'] * (total_bits - hw)
    random.shuffle(bits)
    return int(''.join(bits), 2).to_bytes(total_bits // 8, 'big')

# Generate a random HW value from a truncated normal distribution
def random_hw_normal(min_hw, max_hw, total_bits):
    assert total_bits > 0
    assert total_bits % 8 == 0
    assert min_hw >= 0
    assert max_hw <= total_bits

    dist = {
        'loc'   : total_bits / 2, # mean
        'scale' : sqrt(total_bits / 4) # stdev
    }
    trunc = {
        'a' : (min_hw - dist['loc']) / dist['scale'],
        'b' : (max_hw - dist['loc']) / dist['scale'],
    }
    truncnormgen = truncnorm(**dist, **trunc)

    while True:
        hw = round(truncnormgen.rvs())
        # Skip if it falls outside of required range after rounding (unlikely)
        if hw < min_hw or hw > max_hw:
            continue
        yield hw

# Semi generator functions
def aes_semi_random_generator(key: bytes, min_hw: int, max_hw: int, bias_round: int, bias_operation: str) -> bytes:
    """
    Build a generator providing (`plain`, `cipher`) pairs using AES-128, using `key`.

    Parameters:
        - `key`: AES-128, AES-192 or AES-256 key
        - `min_hw`: Minimum hamming weight of biased state.
        - `max_hw`: Maximum hamming weight of biased state.
        - `bias_round`: Round in which to apply bias.
        - `bias_operation`: Operation _before_ which to apply biased state. 

    Returns:
        - tuple of plain and cipher text matching biased state.

    Example:
    ```
    from tvla_semirandom import aes_semi_random_generator
    from os import urandom

    key = urandom(16)
    tvla_generator = aes_semi_random_generator(key, 0, 8, 5, 'mix_columns')
    for _ in range(1_000):
        (plain, cipher) = next(tvla_generator)
    ```
    """

    assert len(key) in [16, 24, 32]

    ctx = AESSemi(key)
    hwgen = random_hw_normal(min_hw, max_hw, 128)
    while True:
        cipher = ctx.partial_encrypt_block(bias_round, bias_operation, random_with_hw(next(hwgen), 128))
        plain = ctx.decrypt_block(cipher)
        yield (plain, cipher)
