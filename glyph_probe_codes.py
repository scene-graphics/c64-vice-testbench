"""Diagnostic encoding certificate, not a change to the accepted benchmark.

Premise: a pixel's fixed colour function consumes zero, one, or two adjacent
glyph bits. Arbitrary multi-source dependencies are outside this claim.
"""
import random

WIDTH, COUNT = 28, 4096 * 8
FULL = (1 << WIDTH) - 1


def orbit(mask):
    return min(mask, FULL ^ mask)


def quadrants(a, b):
    return (FULL ^ (a | b), (FULL ^ a) & b, a & (FULL ^ b), a & b)


def generate():
    rng = random.Random(0x643332386772)
    codes = [(1 << 14) - 1]
    reserved, singletons = {orbit(codes[0])}, set()
    for index in range(1, COUNT):
        previous = codes[-1]
        ones = [i for i in range(WIDTH) if previous >> i & 1]
        zeros = [i for i in range(WIDTH) if not previous >> i & 1]
        for _ in range(10000):
            candidate = sum(1 << i for i in rng.sample(ones, 7))
            candidate |= sum(1 << i for i in rng.sample(zeros, 7))
            key, edge = orbit(candidate), orbit(previous ^ candidate)
            parts, edges = list(quadrants(previous, candidate)), [edge]
            if key in reserved or edge in reserved:
                continue
            if index == COUNT - 1:
                closing = quadrants(candidate, codes[0])
                closing_edge = orbit(candidate ^ codes[0])
                if any(x.bit_count() != 7 for x in closing):
                    continue
                if closing_edge in reserved or closing_edge in (edge, key):
                    continue
                parts.extend(closing)
                edges.append(closing_edge)
            if len(set(parts)) != len(parts) or any(x in singletons for x in parts):
                continue
            codes.append(candidate)
            reserved.add(key)
            reserved.update(edges)
            singletons.update(parts)
            break
        else:
            raise RuntimeError("finite construction budget exhausted")
    return codes


def validate(codes):
    """Independent complete certificate check, with no random choices."""
    assert len(codes) == COUNT, "certificate:ROM-bit-domain"
    bits, singles, parity = {}, {}, {}
    for index, code in enumerate(codes):
        assert 0 <= code <= FULL and code.bit_count() == 14, "certificate:bit-balance"
        key = orbit(code)
        assert key not in bits, "certificate:bit-identity"
        bits[key] = index
    for index, a in enumerate(codes):
        b = codes[(index + 1) % COUNT]
        for symbol, support in enumerate(quadrants(a, b)):
            assert support.bit_count() == 7, "certificate:all-four-symbols"
            assert support not in singles, "certificate:pair-singleton-identity"
            singles[support] = (index, symbol)
        key = orbit(a ^ b)
        assert key not in bits and key not in parity, "certificate:bit-and-XOR-identity"
        parity[key] = index
    return dict(bit_ids=len(bits), cyclic_adjacent_pairs=len(parity),
                unique_singleton_supports=len(singles),
                bit_and_xor_orbits=len(bits) + len(parity), probes=WIDTH)


def roms(codes):
    """Existing physical bit convention: ROM-byte*8 + column, column0=MSB."""
    validate(codes)
    return [bytes(sum(((codes[byte * 8 + column] >> probe) & 1) << (7 - column)
                      for column in range(8)) for byte in range(4096))
            for probe in range(WIDTH)]
