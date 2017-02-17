# -*- coding: utf-8 -*-
DEFAULT_FILTERS = {
    "Images" : "(mime in [\"image\"])",
    "Videos" : "(mime in [\"video\"])",
    "Audios" : "(mime in [\"audio\"])",
    "Documents" : "(mime in [\"text\",\"application/pdf\",\"application/vnd.oasis.opendocument.text\",\"application/vnd.oasis.opendocument.graphics\",\"application/vnd.oasis.opendocument.presentation\",\"application/vnd.oasis.opendocument.spreadsheet\",\"application/vnd.oasis.opendocument.chart\",\"application/vnd.oasis.opendocument.formula\",\"application/vnd.oasis.opendocument.database\",\"application/vnd.oasis.opendocument.image\"])"
    }
