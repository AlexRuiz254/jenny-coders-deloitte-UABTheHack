class InvestigationAgent:

    def investigate(
        self,
        alert,
        plan,
        context,
        intel,
        initial_evidence
    ):
        ...

    def interpret_evidence(self, evidence, context):
        ...

    def evaluate_check(self, check, available_evidence):
        ...

    def identify_missing_information(self, check_results):
        ...

    def propose_next_queries(self, investigation_state):
        ...

    def generate_findings(self, investigation_state):
        ...

    def summarize_investigation(self, findings):
        ...