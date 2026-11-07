class SOCAPIClient:

    def list_alerts(self, status="new", limit=50,
                    offset=0, desde="", hasta="", rule_id=""):
        ...

    def get_alert(self, alert_id):
        ...

    def get_asset(self, hostname_or_ip):
        ...

    def get_user(self, username_or_upn):
        ...

    def search_logs(self, source, query="",
                    start="", end="", limit=200):
        ...

    def get_intel(self, indicator):
        ...

    def get_sandbox(self, sha256):
        ...

    def get_changes(self, query=""):
        ...