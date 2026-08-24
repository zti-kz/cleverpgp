from cleverpgp.biometrics.liveness import HeadTurnLiveness, LivenessStage


def test_head_turn_liveness_flow() -> None:
    challenge = HeadTurnLiveness(
        neutral_frames_required=2,
        turn_frames_required=2,
        return_frames_required=2,
    )

    assert challenge.update(0.01, True, now=0.0) is LivenessStage.NEUTRAL
    assert challenge.update(0.02, True, now=0.1) is LivenessStage.TURN
    assert challenge.update(0.30, True, now=0.2) is LivenessStage.TURN
    assert challenge.update(0.31, True, now=0.3) is LivenessStage.RETURN
    assert challenge.update(0.02, True, now=0.4) is LivenessStage.RETURN
    assert challenge.update(0.01, True, now=0.5) is LivenessStage.COMPLETE
    assert challenge.progress == 100


def test_static_face_cannot_pass_turn_stage() -> None:
    challenge = HeadTurnLiveness(
        timeout_seconds=1.0,
        neutral_frames_required=1,
        turn_frames_required=1,
    )
    assert challenge.update(0.0, True, now=0.0) is LivenessStage.TURN
    assert challenge.update(0.0, True, now=1.1) is LivenessStage.FAILED
