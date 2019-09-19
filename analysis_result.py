from enum import Enum

class AnalysisResultType(Enum):
    SUCCESS = 1
    ERROR = 2
    NOTAVAILABLE= 3

class AnalysisResult(object):
    def __init__(self, md5):
        self.md5 = md5


class AnalysisResultSuccess(AnalysisResult):

    _type = AnalysisResultType.SUCCESS
    def __init__(self, md5, rule, score):
        super().__init__(md5)
        self.rule = rule
        self.score = score



class AnalysisResultNotAvailable(AnalysisResult):
    _type = AnalysisResultType.NOTAVAILBLE
    def __init__(self, md5):
        super().__init__(md5)


class AnalysisResultError(AnalysisResult):
    _type = AnalysisResultType.ERROR
    def __init__(self, md5, error=True, error_msg="Scaning failed!!!",
                 stop_future_scans=False):
        super().__init__(md5)
        self.error = error
        self.error_msg = error_msg
        self.stop_future_scans = stop_future_scans
