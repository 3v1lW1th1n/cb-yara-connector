import logging

from peewee import Proxy, Model
from peewee import CharField, IntegerField, ForeignKeyField, BooleanField

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#
# autostart must be False if we intend to dynamically create the database.
#
db = Proxy()


class Binary(Model):
    md5 = CharField(index=True, null=False,primary_key=True)
    stop_future_scans = BooleanField(default=False)
    binary_available = BooleanField(null=True, default=True)

    class Meta:
        database = db


class Rule(Model):
    rulename = CharField(index=True, null=False,primary_key=True)

    class Meta:
        database = db


class DetonationResult(Model):
    md5 = ForeignKeyField(Binary, backref="results")
    rule = ForeignKeyField(Rule, backref="results")
    error = BooleanField(null=True, default=False)
    error_msg = CharField(null=True, default="")
    score = IntegerField(default=0)

    class Meta:
        database = db