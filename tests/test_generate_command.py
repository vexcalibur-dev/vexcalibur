import pytest

from vexcalibur.generate_command import GenerateCommandRequest
from vexcalibur.source_options import GenerateSourceOptions
from vexcalibur.sources.osv import OsvConfigurationError, OsvSource


def test_github_command_validates_osv_policy_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validation_calls = 0
    original_validate = OsvSource.validate_before_inventory_load

    def count_validation(source: OsvSource) -> None:
        nonlocal validation_calls
        validation_calls += 1
        original_validate(source)

    monkeypatch.setattr(OsvSource, "validate_before_inventory_load", count_validation)
    request = GenerateCommandRequest(
        input_file=None,
        github_repository="vexcalibur-dev/vexcalibur",
        github_api_url="https://api.github.com",
        github_token_env=None,
        use_gh_auth=False,
        source_options=GenerateSourceOptions(
            findings_file=None,
            offline=False,
            osv_url=None,
            allow_public_osv=False,
        ),
        timestamp=None,
        renderer=None,
    )

    with pytest.raises(OsvConfigurationError, match="--allow-public-osv"):
        request.execute()

    assert validation_calls == 1
