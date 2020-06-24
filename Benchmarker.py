import os, json, time
from SPARQLWrapper import SPARQLWrapper, CSV
from SPARQLWrapper.Wrapper import POSTDIRECTLY
import pandas as pd
from io import StringIO

class TestArgs():
    def __init__(self, rootDBCreds, compDBCreds, queries, ontology, docs):
        self.compDBCreds = compDBCreds
        self.rootDB = SPARQLWrapper(rootDBCreds["Host"] + rootDBCreds["DatabaseName"])
        self.compDBs = [SPARQLWrapper(_dbCreds["Host"] + _dbCreds["DatabaseName"]) for _dbCreds in compDBCreds]
        self.rootDB.setRequestMethod(POSTDIRECTLY)
        self.rootDB.setReturnFormat(CSV)
        for db in self.compDBs:
            db.setRequestMethod(POSTDIRECTLY)
            db.setReturnFormat(CSV)

        self.queries = queries
        self.ontology = ontology
        self.docs = docs

    @staticmethod
    def LoadArgs(dbCredFilePath, qryFilePath, ontFilePath, docsDirPath):
        dbCreds = json.load(open(dbCredFilePath))
        queries =[q for q in open(qryFilePath).read().split("SPARQL") if q]

        ontology = [line for line in open(ontFilePath).read()]
        docs = [open(f) for f in os.listdir(docsDirPath) if os.path.isfile(f)]

        return TestArgs(dbCreds["RootDatabase"], dbCreds["ComparisonDatabases"], queries, ontology, docs)


class Benchmarker():
    def __init__(self, testArgs):
        self.testInfo = testArgs

    #TODO Load Testing

    #TODO Clearing

    #TODO Hot Swaps

    #TODO SPARQL Benchmarks
    def compareQueries(self):
        fields = ["Base Results", "Base Matches", "Base Latency"]
        for cred in self.testInfo.compDBCreds:
            fields.append(cred["DatabaseName"] + "Results")
            fields.append(cred["DatabaseName"] + "Matches")
            fields.append(cred["DatabaseName"] + "Latency")
        data = {f: [] for f in fields}

        curLine = []
        for qry in self.testInfo.queries:
            stTime = time.time()
            self.testInfo.rootDB.setQuery(qry)
            rawResult = self.testInfo.rootDB.query().convert().decode("utf-8")
            groundTruth = pd.read_csv(StringIO(rawResult))
            useCol = groundTruth.columns[0]
            edTime = time.time()

            curLine.append(len(groundTruth))
            curLine.append(len(groundTruth))
            curLine.append(edTime - stTime)

            for db in self.testInfo.compDBs:
                #TODO: handle query errors
                stTime = time.time()
                db.setQuery(qry)
                rawResult = db.query()
                edTime = time.time()
                strResult = rawResult.convert().decode("utf-8")
                res = pd.read_csv(StringIO(strResult))

                curLine.append(len(groundTruth))
                curLine.append(sum([x in groundTruth[useCol] for x in res[useCol]]))
                curLine.append(edTime - stTime)

            for i, item in enumerate(curLine):
                data[fields[i]].append(item)
            curLine.clear()


        return pd.DataFrame(data)

if __name__ == "__main__":
    dbCredFilePath = r"./Config/dbs.json"
    qryFilePath = r"./Config/queries.txt"
    ontFilePath = r"./Config/ontology.txt"
    docsDirPath = r"./Config/Docs"


    bm = Benchmarker(TestArgs.LoadArgs(dbCredFilePath, qryFilePath, ontFilePath, docsDirPath))
    results = bm.compareQueries()
    print(results)
