class TicketBuilder:

    def build(
        self,
        alert,
        investigation,
        verdict,
        severity,
        escalation,
        actions,
        elapsed_seconds
    ):
        ...

    def build_title(self, investigation):
        ...

    def build_summary(self, investigation):
        ...

    def build_evidence(self, findings):
        ...

    def build_affected_entities(self, context):
        ...

    def build_enrichment(self, intel):
        ...

    def build_open_questions(self, investigation):
        ...