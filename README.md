# TVLA Semirandom generators

- Generate "semi random" values for TVLA using biased values in middle rounds.
- ~2000 inputs per second on my laptop.
- Use `scipy`'s `truncnorm` (truncated normal distribution) to respect normal hamming weight distribution of values.

Example:
```
from tvla_semirandom import aes_semi_random_generator
from os import urandom

key = urandom(16)
tvla_generator = aes_semi_random_generator(key, 0, 8, 5, 'mix_columns')
for _ in range(1_000):
    (plain, cipher) = next(tvla_generator)
```

Investigate the intermediate states:

```
from tvla_semirandom import aes_semi_random_generator, AESSemi
from os import urandom

tvla_generator = aes_semi_random_generator(key, 0, 8, 12, 'sub_bytes')
plain, cipher = next(tvla_generator)
AESSemi(key, print_states=True).encrypt_block(plain)

# Outputs:
#   0 add_round_key   65f44af03eba41f564c28fff3a96abeb
#   1 sub_bytes       681960c160d74526a603a613d8ffd33c
#   1 shift_rows      45d4d078d00e6ef7247b247d611666eb
#   1 mix_columns     450e24ebd07b66782416d0f761d46e7d
#   1 add_round_key   57de252828f4ef8655948b5fb61deee3
#   2 sub_bytes       f3d646623215d199ecdf6abc84ebcd7a
#   2 shift_rows      0df65aaa23593eeece9e02655fe9bdda
#   2 mix_columns     0d5902da239ebdaacee95aee5ff63e65
#   2 add_round_key   296325e3e87239091307ba3de48f7ae3
#   3 sub_bytes       67a8e1f1f8d4f9c8c1605310d481eb19
#   3 shift_rows      85c2f8a1414899e878d0edca480ce9d4
#   3 mix_columns     8548edd441d0e9a1780cf8e848c299ca
#   3 add_round_key   f0ed6b82a17ba0a3f49bbcb79eade60c
#   4 sub_bytes       504e89e51b397cdbf792812caf52f80e
#   4 shift_rows      532fa7d9af1210b9684f0c71790041ab
#   4 mix_columns     53120cabaf4f41d96800a7b9792f1071
#   4 add_round_key   37c8bfa60c2b124dce23ed76e266e556
#   5 sub_bytes       6d710c7346346159565b774f4a10ee95
#   5 shift_rows      3ca3fe8f5a18efcbb139f584d6ca282a
#   5 mix_columns     3c18f52a5a39288fb1cafecbd6a3ef84
#   5 add_round_key   8f22abfd58dfb9fa09ecda712225273e
#   6 sub_bytes       edb962b48006accbd23cf2dbc80a1196
#   6 shift_rows      5556aa8dcd6f911fb5eb89b9e8678290
#   6 mix_columns     556f8990cdeb828db567aa1fe85691b9
#   6 add_round_key   029b9822a810b5246d81bc371955578d
#   7 sub_bytes       4927e970a9b3b762f45a244828f8c431
#   7 shift_rows      3bcc1e51d36da9aabfbe365234411cc7
#   7 mix_columns     3b6d36c7d3be1c51bf411eaa34cca952
#   7 add_round_key   307c688329c1a66e12b527cadc05479d
#   8 sub_bytes       95727daf5416a673b4b20f7d902d5982
#   8 shift_rows      2a40ff792047248f8d3776ff60d8cb13
#   8 mix_columns     2a4776132037cb798dd8ff8f604024ff
#   8 add_round_key   f82db469ab71116e02b33aaedb737221
#   9 sub_bytes       8fe30512dd1ca253ed0511ec0568cadf
#   9 shift_rows      73116bc9c19c3aed556b82ce6b45749e
#   9 mix_columns     739c829ec16b74c955456bed6b113ace
#   9 add_round_key   455349ac994202cee38fea1011c94711
#  10 sub_bytes       fdf2303b5c347b4480febb2d3e900833
#  10 shift_rows      548904e24a18211bcdbbead8b26030c3
#  10 mix_columns     5418eac34abb30e2cd60041bb28921d8
#  10 add_round_key   a982dd939095ac8a3e1a881e06000ace
#  11 sub_bytes       05c8fffd4ab23dd90b8b320fed8a0821
#  11 shift_rows      6be81654d63727352b3d2376557e30fd
#  11 mix_columns     6b3723fdd63d30542b7e163555e82776
#  11 add_round_key   519d064894a877c4f7d8267fd88169dc
#  12 sub_bytes       00420800000100060000008000000001
#  12 shift_rows      632c3063637c636f636363cd6363637c
#  12 mix_columns     637c637c636363636363306f632c63cd
#  12 add_round_key   5d425d42636363633c9ad1281c53c56b
#  13 sub_bytes       ddf1be4d39f7113f539f196598dc0fc9
#  13 shift_rows      c1a1aee312688275eddbd44d468676dd
#  13 mix_columns     c168d4dd12db76e3ed86ae7546a1824d
#  13 add_round_key   28ab6645c7c61b468b66b3eebbcf2f73
#  14 sub_bytes       26071c375dc316f6e6bb98a10e936de1
#  14 shift_rows      f7c59c9a4c2e47428eea4632abdc3cf8
#  14 add_round_key   f72e46f84cea3c9a8edc9c42abc54732
# b'}\xb1\xea"\x9c\xe1\xe2\x1c1\xd2\x8a\x89\x90D\x9b['
```

# Run tests

`python -m unittest`

# Build wheel and sdist

`python -m build`

# Install

`pip install tvla_semirandom-x.x.x.tar.gz` or `pip install tvla_semirandom-x.x.x.whl`