import nltk
nltk.data.path.append('/root/nltk_data')
from textblob import TextBlob
import urllib.parse
import urllib.request


def analyze(st):
    blob = TextBlob(st)
    res = {
        "polarity": 0,
        "subjectivity": 0
    }

    for sentence in blob.sentences:
        res["subjectivity"] = res["subjectivity"] + sentence.sentiment.subjectivity
        res["polarity"] = res["polarity"] + sentence.sentiment.polarity

    total = len(blob.sentences)

    res["sentence_count"] = total
    res["polarity"] = res["polarity"] / total
    res["subjectivity"] = res["subjectivity"] / total


# def transfer_param_and_retval(param, retval):
#     values = {"param": param, "retval": retval}
#     data = urllib.parse.urlencode(values)
#     data = data.encode('ascii')
#     req = urllib.request.Request('http://127.0.0.1:7000/', data)
#     with urllib.request.urlopen(req) as resp:
#         data = resp.read()

# p1 = "Personally I like functions to do one thing and only one thing well, it makes them more readable."
# p2 = "Functions are great and proven to be awesome."
# p3 = "The hotel was clean, but the area was terrible."

# transfer_param_and_retval([p1, p2, p3], [])

def handler(param):
    r1 = analyze(param['p1'])
    r2 = analyze(param['p2'])
    r3 = analyze(param['p3'])


fn_name = 'testcases/fn_py_sentiment'

# transfer_param_and_retval([], [r1, r2, r3])
