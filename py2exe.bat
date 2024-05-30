python -m PyInstaller --noconfirm --log-level=WARN ^
    --onefile --noconsole ^
    --add-data "icon-sniffer.png;." ^
    --icon=icon-sniffer.png ^
    snifferPlus.py
