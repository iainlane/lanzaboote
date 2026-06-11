''
  import json

  def collect_pcr_indices(preds):
    """Extract the set of PCR indices from systemd-pcrlock predict output."""
    indices = set()
    entries = []
    if isinstance(preds, dict):
      for bank_entries in preds.values():
        entries.extend(bank_entries)
    elif isinstance(preds, list):
      entries = preds
    for entry in entries:
      if "pcr" in entry:
        indices.add(entry["pcr"])
    return indices
''
