import os
import pytz
import pandas as pd
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo import DESCENDING
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

# Configuration constants
REPORTING_SQL_SERVER = '127.0.0.1'
REPORTING_SQL_PORT = '3306'
REPORTING_SQL_DATABASE = 'myreportingdatabase'
AUDIT_SERVER = "127.0.0.1:27018"
AUDIT_REPLICASET = "rs4"
SERVER_A = "127.0.0.1:27017"
SERVER_B = "127.0.0.1:27017"
SERVER_C = "127.0.0.1:27017"
REPLICASET_A = "rs0"
REPLICASET_B = "rs1"
REPLICASET_C = "rs2"
ARC_MONGO_PORT = '27017'
ARC_MONGO_AUTHMECHANISM = "SCRAM-SHA-1"
ARC_MONGO_AUTHSOURCE = "admin"
ARC_MONGO_DATABASE = 'admin'
ARC_MONGO_READ_PREFERENCE = "secondary"
REPORTING_AULDATALEAK_TABLENAME = "auldata_leak"
MY_OFFER_NAME = "MYOFFERNAME"

# Database credentials (you can use environment variables)
REPORTING_SQL_USERNAME = os.environ.get('REPORTING_SQL_USERNAME')
REPORTING_SQL_PASSWORD = os.environ.get('REPORTING_SQL_PASSWORD')
AUDIT_USERNAME = os.environ.get('MONGO_AUDIT_USERNAME')
AUDIT_PASSWORD = os.environ.get('MONGO_AUDIT_PASSWORD')
MONGO_USERNAME = os.environ.get('mongo_USERNAME')
MONGO_PASSWORD = os.environ.get('mongo_PASSWORD')


def get_mongo_client(mongoServers: str, mongoReplicaset: str, username: str, password: str):
    try:
        mongo_uri = f'mongodb://{username}:{password}@{mongoServers}'
        return MongoClient(mongo_uri, replicaSet=mongoReplicaset, authSource=ARC_MONGO_AUTHSOURCE,
                           readPreference=ARC_MONGO_READ_PREFERENCE, authMechanism=ARC_MONGO_AUTHMECHANISM)
    except Exception as e:
        raise ConnectionError(f"Failed to connect to MongoDB: {e}")


def connect_to_mysql():
    try:
        mysql_uri = f'mysql://{REPORTING_SQL_USERNAME}:{REPORTING_SQL_PASSWORD}@{REPORTING_SQL_SERVER}:{REPORTING_SQL_PORT}/{REPORTING_SQL_DATABASE}?charset=utf8'
        return create_engine(mysql_uri, pool_recycle=3600)
    except SQLAlchemyError as e:
        raise ConnectionError(f"Failed to connect to MySQL: {e}")


def run_mongo_query(collection: Collection, query: dict, project: dict = None, sort: bool = True,
                    sort_field: str = 'eventTime', limit_results: bool = False, limit_count: int = 10):
    try:
        results = []
        db_query = collection.find(query, project) if project is not None else collection.find(query)

        if sort:
            db_query.sort(sort_field, DESCENDING)
        if limit_results:
            db_query.limit(limit_count)

        results = list(db_query)
        results_df = pd.DataFrame(results)
        return results_df
    except Exception as e:
        raise RuntimeError(f"Failed to execute MongoDB query: {e}")


def run_mongo_aggregate(collection: Collection, pipeline: list):
    try:
        results = collection.aggregate(pipeline, cursor={})
        results_df = pd.DataFrame(list(results))
        return results_df
    except Exception as e:
        raise RuntimeError(f"Failed to execute MongoDB aggregation: {e}")


def create_mysql_table(sql_client, query, table_name):
    try:
        sql_client.execute(query)
        return 0
    except SQLAlchemyError as e:
        raise RuntimeError(f"Failed to create MySQL table: {e}")


def init_aludata_leak_reporting_table(client):
    try:
        print('Creating table... ' + REPORTING_AULDATALEAK_TABLENAME)

        reporting_table_create_query = f'CREATE TABLE IF NOT EXISTS {REPORTING_AULDATALEAK_TABLENAME} ( \
                                    `SUBSCRIBERID` VARCHAR(100), \
                                    `MDN` VARCHAR(100), \
                                    `BAN` VARCHAR(100), \
                                    `USAGESTART` DATETIME, \
                                    `USAGEEND` DATETIME, \
                                    `TOTALMB` DECIMAL, \
                                    `AUDITDATE` DATETIME \
                                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;'

        reporting_table_create_index = f'CREATE INDEX idx_AUDITDATE \
                                        ON {REPORTING_AULDATALEAK_TABLENAME} (AUDITDATE);'

        create_mysql_table(client, reporting_table_create_query, REPORTING_AULDATALEAK_TABLENAME)
        create_mysql_table(client, reporting_table_create_index, REPORTING_AULDATALEAK_TABLENAME)
    except Exception as e:
        raise RuntimeError(f"Failed to initialize aludata_leak_reporting_table: {e}")


def get_auldata_subscribers(audit_range_start: datetime, audit_range_end: datetime):
    try:
        audit_client = get_mongo_client(AUDIT_SERVER, AUDIT_REPLICASET, AUDIT_USERNAME, AUDIT_PASSWORD)[ARC_MONGO_DATABASE]
        audit_collection = audit_client[AUDIT_COLLECTION]

        audit_query = [
        {
            "$match": {
                "$and": [
                    {
                        "details": {
                            "$elemMatch": {
                                "state": "ADD",
                                "data.payload.payloads": {
                                    "$elemMatch": {
                                        "requestpayload.subscriptions": {
                                            "$elemMatch": {
                                                "offerName": MY_OFFER_NAME
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    {
                        "lastModifiedDate": {
                            "$gte": audit_range_start,
                            "$lte": audit_range_end
                        }
                    }
                ]
            }
        },
        {
            "$unwind": {
                "path": "$details"
            }
        },
        {
            "$match": {
                "details.state": "ADD",
                "details.data.payload.payloads": {
                    "$elemMatch": {
                        "requestpayload.subscriptions": {
                            "$elemMatch": {
                                "offerName": MY_OFFER_NAME
                            }
                        }
                    }
                }
            }
        },
        {
            "$unwind": {
                "path": "$details.data.payload.payloads"
            }
        },
        {
            "$unwind": {
                "path": "$details.data.payload.payloads.requestpayload.subscriptions"
            }
        },
        {
            "$project": {
                "_id": 0.0,
                "ban": 1.0,
                "subscriberId": "$details.data.payload.subscriberId",
                "effectiveDate": "$details.data.payload.payloads.requestpayload.subscriptions.effectiveDate",
                "expiryDate": "$details.data.payload.payloads.requestpayload.subscriptions.expiryDate"
            }
        }
    ]

        return run_mongo_aggregate(audit_collection, audit_query)
    except Exception as e:
        raise RuntimeError(f"Failed to get auldata subscribers: {e}")


def run_compare_on_node(node: str, sub_list):
    audit_date = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    arc_usage_server = ""
    arc_usage_replicaset = ""

    if node == "A":
        arc_usage_server = SERVER_A
        arc_usage_replicaset = REPLICASET_A
    elif node == "B":
        arc_usage_server = SERVER_B
        arc_usage_replicaset = REPLICASET_B
    elif node == "C":
        arc_usage_server = SERVER_C
        arc_usage_replicaset = REPLICASET_C

    if len(sub_list) > 0:
        usage_client = get_mongo_client(arc_usage_server, arc_usage_replicaset, MONGO_USERNAME, MONGO_PASSWORD)[ARC_MONGO_DATABASE]
        usage_collection = usage_client[COLLECTION]
        usage_result = pd.DataFrame(columns=['extSubId', 'MDN', 'BAN', 'start', 'end', 'bytesIn', 'bytesOut'])

        for subscriber in sub_list:
            effective_date = datetime.strptime(subscriber["effectiveDate"], '%Y-%m-%dT%H:%M:%SZ').astimezone(pytz.timezone('US/Eastern'))
            expiry_date = datetime.strptime(subscriber["expiryDate"], '%Y-%m-%dT%H:%M:%SZ').astimezone(pytz.timezone('US/Eastern'))

            usage_query = {"$and": [
                {"end": {"$gte": effective_date, "$lte": expiry_date}},
                {"extSubId": eval(subscriber["subscriberId"])},
                {"usageType": "OVER"},
                {"$or": [{"bytesIn": {"$gt": 0}, "bytesOut": {"$gt": 0}}]}
            ]}
            usage_project = {"_id": 0, "extSubId": 1, "MDN": 1, "BAN": 1, "start": 1, "end": 1, "bytesIn": 1, "bytesOut": 1}
            query_result = run_mongo_query(usage_collection, usage_query, usage_project)
            usage_result = pd.concat([usage_result, query_result], axis=0)

        if not usage_result.empty:
            usage_result_reporting_query = f"INSERT INTO {REPORTING_AULDATALEAK_TABLENAME} (SUBSCRIBERID, MDN, BAN, USAGESTART, USAGEEND, TOTALMB, AUDITDATE) VALUES "
            for index, row in usage_result.iterrows():
                usage_result_reporting_query = usage_result_reporting_query + f"(\'{row['extSubId']}\', {row['MDN']}, {row['BAN']}, \'{row['start']}\', \'{row['end']}\', \'{int(row['bytesIn']) + int(row['bytesOut'])}\', \'{audit_date}\'),"
            usage_result_reporting_query = usage_result_reporting_query[:-1]
            reporting_client.execute(usage_result_reporting_query)
            print(f"{usage_result.shape[0]} rows written to {REPORTING_AULDATALEAK_TABLENAME}")


def compare(auldata_subs):
    sub_list_a = []
    sub_list_b = []
    sub_list_c = []

    for _, row in auldata_subs.iterrows():
        remainder = int(row["ban"]) % 3
        if remainder == 0:
            sub_list_a.append(row)
        elif remainder == 1:
            sub_list_b.append(row)
        elif remainder == 2:
            sub_list_c.append(row)

    run_compare_on_node("A", sub_list_a)
    run_compare_on_node("B", sub_list_b)
    run_compare_on_node("C", sub_list_c)


def aludata_leak_reporting_table_cleanup(client):
    reporting_table_delete_query = f"DELETE FROM {REPORTING_AULDATALEAK_TABLENAME} WHERE AUDITDATE < DATE_SUB(NOW(), INTERVAL 1 MONTH)"
    client.execute(reporting_table_delete_query)


if __name__ == '__main__':
    try:
        reporting_client = connect_to_mysql()
        init_aludata_leak_reporting_table(reporting_client)
        audit_date = date.today() - timedelta(days=1)
        audit_range_start = datetime.combine(audit_date, time(0, 0, 0))
        audit_range_end = datetime.combine(audit_date, time(23, 59, 59))

        auldata_subs = get_auldata_subscribers(audit_range_start, audit_range_end)
        compare(auldata_subs)
        aludata_leak_reporting_table_cleanup(reporting_client)
    except Exception as e:
        print(f"An error occurred: {e}")