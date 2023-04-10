# TVLA Semirandom generators

- Generate "semi random" values for TVLA using biased values in middle rounds.
- ~2000 inputs per second on my laptop.
- Use `scipy`'s `truncnorm` (truncated normal distribution) to respect normal hamming weight distribution of values.

Example:
```
from tvla_semirandom import aes128_semi_random_generator
from os import urandom

key = urandom(16)
tvla_generator = aes128_semi_random_generator(key, 0, 8, 5, 'mix_columns')
for _ in range(1_000):
    (plain, cipher) = next(tvla_generator)
```

# `sdist`

Build:

`python setup.py sdist`

Install:

`pip install tvla_semirandom-0.0.1.tar.gz`