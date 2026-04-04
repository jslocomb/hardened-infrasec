.PHONY: report report-html report-pdf clean install

VENV     := .venv
PYTHON   := $(VENV)/bin/python
PIP      := $(VENV)/bin/pip
CONTROLS := controls.yaml
OUT_DIR  := reports

install: $(VENV)/bin/activate

$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install -q -r requirements.txt
	touch $(VENV)/bin/activate

report: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR)

report-html: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR) --html-only

report-pdf: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR) --pdf-only

report-by-risk: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR) --sort risk

clean:
	rm -rf $(OUT_DIR)/*.html $(OUT_DIR)/*.pdf
