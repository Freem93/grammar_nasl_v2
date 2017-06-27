#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87248);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/04/28 18:52:10 $");

  script_cve_id(
    "CVE-2015-6788",
    "CVE-2015-6789",
    "CVE-2015-6790",
    "CVE-2015-6791",
    "CVE-2015-8045",
    "CVE-2015-8047",
    "CVE-2015-8048",
    "CVE-2015-8049",
    "CVE-2015-8050",
    "CVE-2015-8054",
    "CVE-2015-8055",
    "CVE-2015-8056",
    "CVE-2015-8057",
    "CVE-2015-8058",
    "CVE-2015-8059",
    "CVE-2015-8060",
    "CVE-2015-8061",
    "CVE-2015-8062",
    "CVE-2015-8063",
    "CVE-2015-8064",
    "CVE-2015-8065",
    "CVE-2015-8066",
    "CVE-2015-8067",
    "CVE-2015-8068",
    "CVE-2015-8069",
    "CVE-2015-8070",
    "CVE-2015-8071",
    "CVE-2015-8401",
    "CVE-2015-8402",
    "CVE-2015-8403",
    "CVE-2015-8404",
    "CVE-2015-8405",
    "CVE-2015-8406",
    "CVE-2015-8407",
    "CVE-2015-8408",
    "CVE-2015-8409",
    "CVE-2015-8410",
    "CVE-2015-8411",
    "CVE-2015-8412",
    "CVE-2015-8413",
    "CVE-2015-8414",
    "CVE-2015-8415",
    "CVE-2015-8416",
    "CVE-2015-8417",
    "CVE-2015-8418",
    "CVE-2015-8419",
    "CVE-2015-8420",
    "CVE-2015-8421",
    "CVE-2015-8422",
    "CVE-2015-8423",
    "CVE-2015-8424",
    "CVE-2015-8425",
    "CVE-2015-8426",
    "CVE-2015-8427",
    "CVE-2015-8428",
    "CVE-2015-8429",
    "CVE-2015-8430",
    "CVE-2015-8431",
    "CVE-2015-8432",
    "CVE-2015-8433",
    "CVE-2015-8434",
    "CVE-2015-8435",
    "CVE-2015-8436",
    "CVE-2015-8437",
    "CVE-2015-8438",
    "CVE-2015-8439",
    "CVE-2015-8440",
    "CVE-2015-8441",
    "CVE-2015-8442",
    "CVE-2015-8443",
    "CVE-2015-8444",
    "CVE-2015-8445",
    "CVE-2015-8446",
    "CVE-2015-8447",
    "CVE-2015-8448",
    "CVE-2015-8449",
    "CVE-2015-8450",
    "CVE-2015-8451",
    "CVE-2015-8452",
    "CVE-2015-8453",
    "CVE-2015-8454",
    "CVE-2015-8455",
    "CVE-2015-8456",
    "CVE-2015-8457",
    "CVE-2015-8548"
  );
  script_bugtraq_id(
    78710,
    78712,
    78713,
    78714,
    78715,
    78716,
    78717,
    78718,
    78802
  );
  script_osvdb_id(
    131208,
    131209,
    131210,
    131211,
    131212,
    131213,
    131214,
    131215,
    131216,
    131217,
    131218,
    131219,
    131220,
    131221,
    131222,
    131223,
    131224,
    131225,
    131226,
    131227,
    131228,
    131229,
    131230,
    131231,
    131232,
    131233,
    131234,
    131235,
    131236,
    131237,
    131238,
    131239,
    131240,
    131241,
    131242,
    131243,
    131244,
    131245,
    131246,
    131247,
    131248,
    131249,
    131250,
    131251,
    131252,
    131253,
    131254,
    131255,
    131256,
    131257,
    131258,
    131259,
    131260,
    131261,
    131262,
    131264,
    131265,
    131266,
    131267,
    131268,
    131269,
    131270,
    131271,
    131272,
    131273,
    131274,
    131275,
    131276,
    131277,
    131278,
    131279,
    131280,
    131281,
    131282,
    131283,
    131464,
    131465,
    131351,
    131352,
    131353,
    131463,
    131366,
    131367,
    131368,
    131369,
    131466,
    131467,
    131672
  );

  script_name(english:"Google Chrome < 47.0.2526.80 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 47.0.2526.80. It is, therefore, affected by multiple
vulnerabilities :

  - A type confusion error exists related to extensions that
    allows an attacker to have an unspecified impact.
    (CVE-2015-6788)

  - A use-after-free error exists in Blink that is triggered
    when handling updates. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2015-6789)

  - An unspecified escaping issue exists in saved pages.
    (CVE-2015-6790)

  - Multiple unspecified vulnerabilities exist that an
    attacker can exploit to have an unspecified impact.
    (CVE-2015-6791)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-8438, CVE-2015-8446)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8045,
    CVE-2015-8047, CVE-2015-8060, CVE-2015-8408,
    CVE-2015-8416, CVE-2015-8417, CVE-2015-8418,
    CVE-2015-8419, CVE-2015-8443, CVE-2015-8444,
    CVE-2015-8451, CVE-2015-8455)

  - Multiple security bypass vulnerabilities exist that
    allow an attacker to write arbitrary data to the file
    system under user permissions. (CVE-2015-8453,
    CVE-2015-8440,  CVE-2015-8409)

  - A stack buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8407,
    CVE-2015-8457)

  - A type confusion error exists that allows an attacker to
    execute arbitrary code. (CVE-2015-8439, CVE-2015-8456)

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8445)

  - A buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8415)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8048,
    CVE-2015-8049, CVE-2015-8050, CVE-2015-8055,
    CVE-2015-8056, CVE-2015-8057, CVE-2015-8058,
    CVE-2015-8059, CVE-2015-8061, CVE-2015-8062,
    CVE-2015-8063, CVE-2015-8064, CVE-2015-8065,
    CVE-2015-8066, CVE-2015-8067, CVE-2015-8068,
    CVE-2015-8069, CVE-2015-8070, CVE-2015-8071,
    CVE-2015-8401, CVE-2015-8402, CVE-2015-8403,
    CVE-2015-8404, CVE-2015-8405, CVE-2015-8406,
    CVE-2015-8410, CVE-2015-8411, CVE-2015-8412,
    CVE-2015-8413, CVE-2015-8414, CVE-2015-8420,
    CVE-2015-8421, CVE-2015-8422, CVE-2015-8423,
    CVE-2015-8424, CVE-2015-8425, CVE-2015-8426,
    CVE-2015-8427, CVE-2015-8428, CVE-2015-8429,
    CVE-2015-8430, CVE-2015-8431, CVE-2015-8432,
    CVE-2015-8433, CVE-2015-8434, CVE-2015-8435,
    CVE-2015-8436, CVE-2015-8437, CVE-2015-8441,
    CVE-2015-8442, CVE-2015-8447, CVE-2015-8448,
    CVE-2015-8449, CVE-2015-8450, CVE-2015-8452,
    CVE-2015-8454)

  - A flaw exists in Google V8 in serialize.cc that is
    triggered when handling alignment for deferred objects.
    An attacker can exploit this to have an unspecified
    impact. (CVE-2015-8548)");
  # http://googlechromereleases.blogspot.com/2015/12/stable-channel-update_8.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?a6b6361f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 47.0.2526.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'47.0.2526.80', severity:SECURITY_HOLE);
