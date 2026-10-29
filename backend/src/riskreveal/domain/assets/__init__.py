"""Assets domain: the machines RiskReveal knows about.

Deliberately does not import ``models`` here, so light modules in this
package stay importable without SQLAlchemy. Import models explicitly:
``from riskreveal.domain.assets.models import Asset``.
"""
