from abc import ABC, abstractmethod

class BaseInvestigationStrategy(ABC):

    @abstractmethod
    def build_plan(self, alert):
        ...

    @abstractmethod
    def get_required_checks(self, rule_id):
        ...

    @abstractmethod
    def get_relevant_sources(self, rule_id):
        ...

    def evaluate_checks(self, evidence, context):
        ...