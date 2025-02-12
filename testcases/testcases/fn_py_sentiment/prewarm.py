import nltk
nltk.data.path.append('/root/nltk_data')
from textblob import TextBlob
import urllib.parse
import urllib.request

# prewarm
blob = TextBlob("The hotel was clean, but the area was terrible.")
for sentence in blob.sentences:
        sentence.sentiment.subjectivity
        sentence.sentiment.polarity

# prewarm
b'xn--o3cw4h'.decode('idna')
