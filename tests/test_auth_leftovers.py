# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The one authentication path the earlier test files leave: a delivery outcome for a challenge
whose account has gone. Synthetic account only.
"""

from types import SimpleNamespace

import pytest

from carlos_patient_portal import auth
from tests.test_auth_refusals import signed_in


def state(app, keys, token):
    with app.state.session_factory() as session:
        return auth.get_mfa_challenge_delivery_state(
            session, token, challenge_token_secret=keys.mfa
        )


def test_an_outcome_for_a_challenge_whose_account_is_gone_is_not_found() -> None:
    app, payload, keys, _ = signed_in()
    delivery = state(app, keys, payload["mfa_challenge_token"])
    answers = iter([SimpleNamespace(account_id=1, id=1), None])  # the challenge, then no account

    class Session:
        def scalar(self, statement):
            return next(answers)

    with pytest.raises(auth.MfaChallengeNotFoundError):
        auth.record_mfa_delivery_outcome(Session(), delivery=delivery, outcome="success")
