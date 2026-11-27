# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The Merkle tree behind a clinic transparency log (carlos-portal#37): hashing, proofs, checks.

**Inert.** Nothing imports this module: there is no table, no route, no signed head and no job
that uses it. It is the first, pure step of #37 (the clinic's append-only log of salted document
hashes), built so that the tree arithmetic can be reviewed and tested against published vectors
before any decision about storing or serving a log is made (the open questions are on #37).

It follows RFC 9162 (Certificate Transparency version 2), section 2.1, with SHA-256:

- ``MTH({})`` is the hash of the empty string; ``MTH({d})`` is ``HASH(0x00 || d)``; and for
  ``n > 1`` ``MTH(D[n]) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`` where ``k`` is the largest
  power of two smaller than ``n``. The ``0x00``/``0x01`` prefixes keep a leaf from ever being
  read as a node.
- An **inclusion proof** (section 2.1.3) shows that a leaf hash is entry ``leaf_index`` of the
  tree of ``tree_size`` entries with a given root; a **consistency proof** (section 2.1.4) shows
  that the tree of ``first_size`` entries is a prefix of the tree of ``second_size`` entries, so
  that an old entry can neither be removed nor changed without every later root changing.
- The verifiers are the RFC's own algorithms (2.1.3.2 and 2.1.4.2), written to be **total**: any
  malformed argument (a wrong type, a hash that is not 32 bytes, a size or index out of range, a
  proof longer than a tree can need) is simply "not valid", never an exception.

The generators work on **leaf hashes** (``leaf_hash(entry)`` of each entry, in order) and are
reference quality: they recompute subtree roots as they recurse (``O(n log n)`` for a tree of
``n`` entries). A stored log will want a compact-range or tile form; that is for the step that
decides what is stored, and it can be tested against this one.
"""

from collections.abc import Sequence
from hashlib import sha256

HASH_SIZE = 32
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
# A proof for a tree of fewer than 2**63 entries needs at most 64 hashes; a longer one is refused
# before any hashing is done on it.
MAX_PROOF_HASHES = 64
MAX_TREE_SIZE = 2**63 - 1


def leaf_hash(entry: bytes) -> bytes:
    """The hash of one log entry: ``HASH(0x00 || entry)``."""
    return sha256(LEAF_PREFIX + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """The hash of two subtree hashes: ``HASH(0x01 || left || right)``."""
    return sha256(NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    """The root of a tree with no entries: the hash of the empty string."""
    return sha256(b"").digest()


def _largest_power_of_two_below(size: int) -> int:
    """The ``k`` of the RFC: the largest power of two strictly smaller than ``size`` (size >= 2)."""
    return 1 << ((size - 1).bit_length() - 1)


def _check_hashes(hashes: Sequence[bytes]) -> None:
    for value in hashes:
        if type(value) is not bytes or len(value) != HASH_SIZE:
            raise ValueError("a leaf hash is 32 bytes")


def root_from_leaf_hashes(leaf_hashes: Sequence[bytes]) -> bytes:
    """``MTH`` of the tree whose entries have these leaf hashes, in order."""
    _check_hashes(leaf_hashes)
    return _root(leaf_hashes)


def _root(hashes: Sequence[bytes]) -> bytes:
    size = len(hashes)
    if size == 0:
        return empty_root()
    if size == 1:
        return hashes[0]
    k = _largest_power_of_two_below(size)
    return node_hash(_root(hashes[:k]), _root(hashes[k:]))


def merkle_tree_hash(entries: Sequence[bytes]) -> bytes:
    """``MTH`` of a list of entries (each is hashed as a leaf first)."""
    return _root([leaf_hash(entry) for entry in entries])


def inclusion_proof(leaf_hashes: Sequence[bytes], leaf_index: int) -> list[bytes]:
    """The audit path for entry ``leaf_index`` (0-based) of the tree (RFC 9162, 2.1.3.1)."""
    _check_hashes(leaf_hashes)
    if type(leaf_index) is not int or not 0 <= leaf_index < len(leaf_hashes):
        raise ValueError("the leaf index is outside the tree")
    return _path(leaf_index, leaf_hashes)


def _path(index: int, hashes: Sequence[bytes]) -> list[bytes]:
    size = len(hashes)
    if size == 1:
        return []
    k = _largest_power_of_two_below(size)
    if index < k:
        return [*_path(index, hashes[:k]), _root(hashes[k:])]
    return [*_path(index - k, hashes[k:]), _root(hashes[:k])]


def consistency_proof(leaf_hashes: Sequence[bytes], first_size: int) -> list[bytes]:
    """The proof that the tree of the first ``first_size`` entries is a prefix of this tree.

    ``1 <= first_size <= len(leaf_hashes)`` (RFC 9162, 2.1.4.1). Equal sizes give the empty proof.
    """
    _check_hashes(leaf_hashes)
    if type(first_size) is not int or not 1 <= first_size <= len(leaf_hashes):
        raise ValueError("the first tree size is outside the tree")
    return _subproof(first_size, leaf_hashes, True)


def _subproof(first: int, hashes: Sequence[bytes], complete: bool) -> list[bytes]:
    size = len(hashes)
    if first == size:
        return [] if complete else [_root(hashes)]
    k = _largest_power_of_two_below(size)
    if first <= k:
        return [*_subproof(first, hashes[:k], complete), _root(hashes[k:])]
    return [*_subproof(first - k, hashes[k:], False), _root(hashes[:k])]


def _is_hash(value: object) -> bool:
    return type(value) is bytes and len(value) == HASH_SIZE


def _is_proof(proof: object) -> bool:
    return (
        isinstance(proof, (list, tuple))
        and len(proof) <= MAX_PROOF_HASHES
        and all(_is_hash(value) for value in proof)
    )


def _is_size(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_TREE_SIZE


def verify_inclusion(
    leaf: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Whether ``leaf`` (a leaf hash) is entry ``leaf_index`` of the tree of ``tree_size``.

    The tree is the one with the given ``root``. RFC 9162, 2.1.3.2. Anything malformed is "no".
    """
    if not (_is_hash(leaf) and _is_hash(root) and _is_proof(proof)):
        return False
    if not (_is_size(leaf_index) and _is_size(tree_size)) or leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    result = leaf
    for sibling in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            result = node_hash(sibling, result)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            result = node_hash(result, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and result == root


def verify_consistency(
    first_size: int,
    second_size: int,
    first_root: bytes,
    second_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """Whether the first tree (``first_size``, ``first_root``) is a prefix of the second tree.

    The second tree has ``second_size`` entries and ``second_root``. RFC 9162, 2.1.4.2, for
    ``1 <= first_size <= second_size``. A tree of no entries has nothing to be consistent with, so
    it is "no" here. Anything malformed is "no".

    The proof binds the two **roots**: a proof that verifies for one claimed ``second_size`` can
    verify for another size whose tree could have the same shape of right edge, because a verifier
    never sees the entries. The size is a claim about the tree the root names, to be checked where
    the head (size and root) is signed, not something this check adds.
    """
    if not (_is_hash(first_root) and _is_hash(second_root) and _is_proof(proof)):
        return False
    if not (_is_size(first_size) and _is_size(second_size)):
        return False
    if not 1 <= first_size <= second_size:
        return False
    if first_size == second_size:
        return len(proof) == 0 and first_root == second_root
    path = list(proof)
    # A first tree that is a complete subtree is its own first node of the path: the verifier is
    # given its root separately, so it joins the path here.
    if first_size & (first_size - 1) == 0:
        path.insert(0, first_root)
    if not path:
        return False
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    first_computed = second_computed = path[0]
    for node in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            first_computed = node_hash(node, first_computed)
            second_computed = node_hash(node, second_computed)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            second_computed = node_hash(second_computed, node)
        fn >>= 1
        sn >>= 1
    return sn == 0 and first_computed == first_root and second_computed == second_root
