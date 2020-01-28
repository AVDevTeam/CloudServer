import pefile, fnmatch, os, time
import numpy as np
import pandas as pd
from multiprocessing import Pool
from scipy.sparse import csr_matrix
from scipy.sparse import hstack
from sklearn import metrics
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.model_selection import cross_validate, LeaveOneOut, RepeatedKFold
from sklearn.metrics import make_scorer, precision_score, recall_score, f1_score, confusion_matrix
import xgboost as xgb
from xgboost import cv, DMatrix
import pickle
import traceback

class MLPredictor:
    def __init__(self):
        with open("model.pickle", "rb") as f:
            self.booster = pickle.load(f)
        with open("ohe.pickle", "rb") as f:
            self.ohe = pickle.load(f)


    def parse_headers(self, pe):
        headers = {
            'OH.SizeOfCode'                 :pe.OPTIONAL_HEADER.SizeOfCode,
            'OH.SizeOfInitializedData'      :pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'OH.AddressOfEntryPoint'        :pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'OH.BaseOfCode'                 :pe.OPTIONAL_HEADER.BaseOfCode,
            'OH.BaseOfData'                 :pe.OPTIONAL_HEADER.BaseOfData,
            'OH.ImageBase'                  :pe.OPTIONAL_HEADER.ImageBase,
            'OH.MajorOperatingSystemVersion':pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'OH.MajorSubsystemVersion'      :pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'OH.SizeOfImage'                :pe.OPTIONAL_HEADER.SizeOfImage,
            'OH.SizeOfHeaders'              :pe.OPTIONAL_HEADER.SizeOfHeaders,
            'OH.CheckSum'                   :pe.OPTIONAL_HEADER.CheckSum,
            'OH.Subsystem'                  :pe.OPTIONAL_HEADER.Subsystem,
            'OH.DllCharacteristics'         :pe.OPTIONAL_HEADER.DllCharacteristics,
            'OH.SizeOfStackReserve'         :pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'OH.SizeOfStackCommit'          :pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'OH.SizeOfHeapReserve'          :pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'OH.SizeOfHeapCommit'           :pe.OPTIONAL_HEADER.SizeOfHeapCommit,

            'FH.NumberOfSections'           :pe.FILE_HEADER.NumberOfSections,
            'FH.TimeDateStamp'              :pe.FILE_HEADER.TimeDateStamp,
            'FH.Characteristics'            :pe.FILE_HEADER.Characteristics,
        }
        return headers

    def parse_sections(self, pe):
        sections = []
        for entry in pe.sections:
            sect = {
                'SectionName'   :str(entry.Name),
                'SectionSize'   :hex(entry.SizeOfRawData),
                'SectionEntropy':entry.get_entropy()
                }
            sections.append(sect)
        return sections

    def parse_import(self, pe):
        import_table = list()
        import_num = 0
        dll_num = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            dll_num = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                import_entry = dict()
                import_entry['dll'] = entry.dll
                import_entry['symbols'] = list()
                import_num = import_num + len(entry.imports)
                for imp in entry.imports:
                    import_entry['symbols'].append(imp.name)
                import_table.append(import_entry)
        return import_table, import_num, dll_num

    def parse_export(self, pe):
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        return 0

    def size(self, name): return os.path.getsize(name)

    def parse_pe(self, name):
        try:
            pe = pefile.PE(name)
            info = self.parse_headers(pe)
            info['sections'] = self.parse_sections(pe)
            info['export_num'] = self.parse_export(pe)
            info['import'], info['import_num'], info['dll_num'] = self.parse_import(pe)
            pe.close()
            info['sha256'] = name.split('\\')[-1]
            info['size'] = self.size(name)
            return info
        except:
            traceback.print_exc()
            return None
        return None

    def __classify(self, path):
        files = [self.parse_pe(path)]
        df = pd.DataFrame(files)
        df = df.drop(['sha256', 'size'], axis=1)
        sections = df['sections'].apply(pd.Series).stack().reset_index(level=1, drop=True).apply(pd.Series)

        imports = df['import'].apply(pd.Series).stack().reset_index(level=1, drop=True).apply(pd.Series)
        imports = imports.reset_index().set_index(['index', 'dll'])
        imports = imports['symbols'].apply(pd.Series).stack().reset_index(level=2, drop=True).to_frame('import').reset_index().set_index('index')

        join = sections.join(imports).fillna(0)

        join['SectionName'] = join['SectionName'].astype('str')
        join['dll'] = join['dll'].astype('str')
        join['import'] = join['import'].astype('str')

        string_columns = ['SectionName', 'dll', 'import']
        matrix = self.ohe.transform(join[string_columns])

        index = join.index
        rows = []
        for i in index.unique():
            select = index.slice_indexer(start=i, end=i)
            rows.append(csr_matrix(matrix[select].sum(axis=0)))

        join_encoded = pd.DataFrame(data={'matrix':rows})

        df = df.drop(['sections', 'import'], axis=1)
        df = df.join(join_encoded)

        X = df.apply(lambda x: hstack((x.drop('matrix').astype('int64').values, x['matrix'])).T, axis=1)
        X = hstack(X.values).T
        X = X.todok().toarray()
        return self.booster.predict(DMatrix(X))[0]

    def classify(self, path):
        try:
            return self.__classify(path)
        except:
            traceback.print_exc()
            return 0.0
