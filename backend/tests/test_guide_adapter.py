
from backend.app.adapters.guide_adapter import PROJECT_ROOT


def test_guide_adapter_uses_project_root():
    assert PROJECT_ROOT == PROJECT_ROOT.resolve()
    assert (PROJECT_ROOT / "src" / "upload_pipeline.py").is_file()
    assert (PROJECT_ROOT / "src" / "threat_detection.py").is_file()
    assert (PROJECT_ROOT / "src" / "soc_alert_generator.py").is_file()
