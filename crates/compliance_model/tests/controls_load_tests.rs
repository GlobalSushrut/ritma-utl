use compliance_model::load_controls_from_file;

#[test]
fn load_controls_from_file_smoke() {
    let path = "tests/data/sample_controls.json";
    let controls = load_controls_from_file(path).expect("load controls");
    assert!(!controls.is_empty());
    assert_eq!(controls[0].control_id, "AC-3");
}
