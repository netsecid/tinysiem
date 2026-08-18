"""Country name → ISO 3166-1 alpha-2 resolution for the AI search filters.

Covers English + Indonesian names for the countries most likely to appear in
security queries, plus a 2/3-letter ISO passthrough. Unknown names return None
so the filter normalizer can drop them with a visible warning instead of
silently querying garbage.

Full 200-country lists exist (pycountry) but are not worth a dependency for a
security-search filter; the extraction LLM is instructed to prefer ISO codes,
and this map catches the natural-language cases.
"""

# name (lowercase, normalized) → ISO2. EN + ID where they differ.
_COUNTRY_NAMES: dict[str, str] = {
    # ISO passthroughs handled separately (regex), this is only for names.
    "indonesia": "ID", "id": "ID",
    "russia": "RU", "rusia": "RU",
    "united states": "US", "usa": "US", "amerika serikat": "US", "america": "US",
    "united kingdom": "GB", "uk": "GB", "inggris": "GB", "britain": "GB", "britania raya": "GB",
    "netherlands": "NL", "belanda": "NL", "holland": "NL",
    "germany": "DE", "jerman": "DE",
    "france": "FR", "prancis": "FR", "perancis": "FR",
    "china": "CN", "tiongkok": "CN", "cina": "CN",
    "japan": "JP", "jepang": "JP",
    "south korea": "KR", "korea selatan": "KR", "korea": "KR",
    "singapore": "SG", "singapura": "SG",
    "malaysia": "MY",
    "thailand": "TH",
    "vietnam": "VN",
    "philippines": "PH", "filipina": "PH",
    "india": "IN",
    "pakistan": "PK",
    "bangladesh": "BD",
    "australia": "AU",
    "new zealand": "NZ", "selandia baru": "NZ",
    "brazil": "BR", "brasil": "BR",
    "mexico": "MX", "meksiko": "MX",
    "canada": "CA", "kanada": "CA",
    "argentina": "AR",
    "colombia": "CO",
    "chile": "CL", "cile": "CL",
    "venezuela": "VE",
    "peru": "PE", "peru": "PE",
    "nigeria": "NG",
    "egypt": "EG", "mesir": "EG",
    "south africa": "ZA", "afrika selatan": "ZA",
    "kenya": "KE",
    "morocco": "MA", "maroko": "MA",
    "turkey": "TR", "turki": "TR",
    "iran": "IR",
    "iraq": "IQ", "irak": "IQ",
    "israel": "IL",
    "saudi arabia": "SA", "arab saudi": "SA",
    "uae": "AE", "united arab emirates": "AE", "emirat arab bersatu": "AE",
    "qatar": "QA",
    "ukraine": "UA", "ukraina": "UA",
    "poland": "PL", "polandia": "PL",
    "romania": "RO", "rumania": "RO",
    "bulgaria": "BG",
    "hungary": "HU", "hongaria": "HU",
    "czech republic": "CZ", "czechia": "CZ", "republik ceko": "CZ", "ceko": "CZ",
    "slovakia": "SK", "slovakia": "SK",
    "italy": "IT", "italia": "IT",
    "spain": "ES", "spanyol": "ES",
    "portugal": "PT",
    "sweden": "SE", "swedia": "SE",
    "norway": "NO", "norwegia": "NO",
    "denmark": "DK", "denmark": "DK", "denmark": "DK",
    "finland": "FI", "finlandia": "FI",
    "switzerland": "CH", "swiss": "CH",
    "austria": "AT", "austria": "AT",
    "belgium": "BE", "belgia": "BE",
    "ireland": "IE", "irlandia": "IE",
    "greece": "GR", "yunani": "GR",
    "lithuania": "LT", "lituania": "LT",
    "latvia": "LV", "latvia": "LV",
    "estonia": "EE", "estonia": "EE",
    "andorra": "AD",
    "monaco": "MC",
    "luxembourg": "LU", "luksemburg": "LU",
    "iceland": "IS", "islandia": "IS",
    "croatia": "HR", "kroasia": "HR",
    "serbia": "RS", "serbia": "RS",
    "albania": "AL",
    "moldova": "MD", "moldova": "MD",
    "georgia": "GE",
    "armenia": "AM",
    "azerbaijan": "AZ",
    "kazakhstan": "KZ",
    "uzbekistan": "UZ",
    "mongolia": "MN",
    "myanmar": "MM", "burma": "MM",
    "cambodia": "KH", "kamboja": "KH",
    "laos": "LA",
    "north korea": "KP", "korea utara": "KP",
    "taiwan": "TW",
    "hong kong": "HK",
    "macau": "MO",
    "palestine": "PS", "palestina": "PS",
    "jordan": "JO", "yordania": "JO",
    "lebanon": "LB", "libanon": "LB",
    "syria": "SY", "suriah": "SY",
    "yemen": "YE", "yaman": "YE",
    "afghanistan": "AF", "afganistan": "AF",
    "nepal": "NP",
    "sri lanka": "LK", "sri lanka": "LK",
    "fiji": "FJ",
    "papua new guinea": "PG", "papua nugini": "PG",
    "curacao": "CW",
    "panama": "PA",
    "costa rica": "CR", "kosta rika": "CR",
    "ecuador": "EC", "ekuador": "EC",
    "bolivia": "BO",
    "paraguay": "PY",
    "uruguay": "UY",
    "cuba": "CU", "kuba": "CU",
    "jamaica": "JM",
    "dominican republic": "DO", "republik dominika": "DO",
    "honduras": "HN",
    "guatemala": "GT",
    "el salvador": "SV",
    "nicaragua": "NI",
    "puerto rico": "PR",
    "bahamas": "BS",
    "trinidad and tobago": "TT",
    "ghana": "GH",
    "ethiopia": "ET",
    "tanzania": "TZ",
    "uganda": "UG",
    "angola": "AO",
    "mozambique": "MZ",
    "zimbabwe": "ZW",
    "zambia": "ZM",
    "congo": "CD",
    "cameroon": "CM", "kamerun": "CM",
    "ivory coast": "CI", "pantai gading": "CI",
    "senegal": "SN",
    "tunisia": "TN", "tunisia": "TN",
    "algeria": "DZ", "aljazair": "DZ",
    "libya": "LY", "libya": "LY",
    "sudan": "SD",
    "somalia": "SO",
    "new caledonia": "NC",
    "french polynesia": "PF",
    "marshall islands": "MH",
    "solomon islands": "SB",
    "vanuatu": "VU",
    "timor leste": "TL", "timor-leste": "TL", "timor timur": "TL",
    "brunei": "BN",
}

_ISO2_RE = __import__("re").compile(r"^[A-Za-z]{2}$")
_ISO3_RE = __import__("re").compile(r"^[A-Za-z]{3}$")

# Common ISO3 → ISO2 for the few LLMs insist on 3-letter codes.
_ISO3_TO_ISO2 = {
    "IDN": "ID", "RUS": "RU", "USA": "US", "GBR": "GB", "NLD": "NL", "DEU": "DE",
    "FRA": "FR", "CHN": "CN", "JPN": "JP", "KOR": "KR", "SGP": "SG", "MYS": "MY",
    "THA": "TH", "VNM": "VN", "PHL": "PH", "IND": "IN", "PAK": "PK", "BGD": "BD",
    "AUS": "AU", "NZL": "NZ", "BRA": "BR", "MEX": "MX", "CAN": "CA", "ARG": "AR",
    "COL": "CO", "CHL": "CL", "VEN": "VE", "PER": "PE", "NGA": "NG", "EGY": "EG",
    "ZAF": "ZA", "KEN": "KE", "MAR": "MA", "TUR": "TR", "IRN": "IR", "IRQ": "IQ",
    "ISR": "IL", "SAU": "SA", "ARE": "AE", "QAT": "QA", "UKR": "UA", "POL": "PL",
    "ROU": "RO", "BGR": "BG", "HUN": "HU", "CZE": "CZ", "SVK": "SK", "ITA": "IT",
    "ESP": "ES", "PRT": "PT", "SWE": "SE", "NOR": "NO", "DNK": "DK", "FIN": "FI",
    "CHE": "CH", "AUT": "AT", "BEL": "BE", "IRL": "IE", "GRC": "GR", "LTU": "LT",
    "LVA": "LV", "EST": "EE", "AND": "AD", "MCO": "MC", "LUX": "LU", "ISL": "IS",
    "HRV": "HR", "SRB": "RS", "ALB": "AL", "MDA": "MD", "GEO": "GE", "ARM": "AM",
    "AZE": "AZ", "KAZ": "KZ", "UZB": "UZ", "MNG": "MN", "MMR": "MM", "KHM": "KH",
    "LAO": "LA", "PRK": "KP", "TWN": "TW", "HKG": "HK", "MAC": "MO", "PSE": "PS",
    "JOR": "JO", "LBN": "LB", "SYR": "SY", "YEM": "YE", "AFG": "AF", "NPL": "NP",
    "LKA": "LK", "FJI": "FJ", "PNG": "PG", "CUW": "CW", "PAN": "PA", "CRI": "CR",
    "ECU": "EC", "BOL": "BO", "PRY": "PY", "URY": "UY", "CUB": "CU", "JAM": "JM",
    "DOM": "DO", "HND": "HN", "GTM": "GT", "SLV": "SV", "NIC": "NI", "PRI": "PR",
    "BHS": "BS", "TTO": "TT", "GHA": "GH", "ETH": "ET", "TZA": "TZ", "UGA": "UG",
    "AGO": "AO", "MOZ": "MZ", "ZWE": "ZW", "ZMB": "ZM", "COD": "CD", "CMR": "CM",
    "CIV": "CI", "SEN": "SN", "TUN": "TN", "DZA": "DZ", "LBY": "LY", "SDN": "SD",
    "SOM": "SO", "NCL": "NC", "PYF": "PF", "MHL": "MH", "SLB": "SB", "VUT": "VU",
    "TLS": "TL", "BRN": "BN",
}


def to_code(value: str) -> str | None:
    """Resolve a country reference to an uppercase ISO 3166-1 alpha-2 code.

    Accepts: ISO2 ("id", "RU"), ISO3 ("IDN", "rus"), and common English or
    Indonesian country names ("Indonesia", "Rusia", "United States").
    Returns None when the value can't be resolved (caller drops it with a note).
    """
    if not value:
        return None
    v = str(value).strip()
    if not v:
        return None
    if _ISO2_RE.match(v):
        return v.upper()
    if _ISO3_RE.match(v):
        return _ISO3_TO_ISO2.get(v.upper())
    return _COUNTRY_NAMES.get(v.lower())
