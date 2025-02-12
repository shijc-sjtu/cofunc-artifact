import datetime
import io
import os
import sys
import uuid
from urllib.parse import unquote_plus
from PIL import Image

import storage
client = storage.storage.get_instance()
