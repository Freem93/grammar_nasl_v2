#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81648);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-1212",
    "CVE-2015-1213",
    "CVE-2015-1214",
    "CVE-2015-1215",
    "CVE-2015-1216",
    "CVE-2015-1217",
    "CVE-2015-1218",
    "CVE-2015-1219",
    "CVE-2015-1220",
    "CVE-2015-1221",
    "CVE-2015-1222",
    "CVE-2015-1223",
    "CVE-2015-1224",
    "CVE-2015-1225",
    "CVE-2015-1226",
    "CVE-2015-1227",
    "CVE-2015-1228",
    "CVE-2015-1229",
    "CVE-2015-1230",
    "CVE-2015-1231",
    "CVE-2015-1232",
    "CVE-2015-2239"
  );
  script_bugtraq_id(
    72497,
    72901,
    72912,
    72916,
    73349,
    74855
  );
  script_osvdb_id(
    116794,
    118996,
    118997,
    118998,
    118999,
    119000,
    119001,
    119002,
    119003,
    119004,
    119005,
    119006,
    119007,
    119008,
    119009,
    119010,
    119011,
    119012,
    119013,
    119022,
    119026,
    119027,
    119028,
    119029,
    119030,
    119031,
    119032,
    119033,
    119034,
    119035,
    119036,
    119037,
    119038,
    119039,
    119040,
    119041,
    119050
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Google Chrome < 41.0.2272.76 Multiple Vulnerabilities (Mac OS X) (FREAK)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 41.0.2272.76. It is, therefore, affected by the following
vulnerabilities :

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to
    the support of weak EXPORT_RSA cipher suites with keys
    less than or equal to 512 bits. A man-in-the-middle
    attacker may be able to downgrade the SSL/TLS connection
    to use EXPORT_RSA cipher suites which can be factored in
    a short amount of time, allowing the attacker to
    intercept and decrypt the traffic. (CVE-2015-0204)

  - Multiple out-of-bounds write errors exist in skia
    filters and media. (CVE-2015-1212, CVE-2015-1213,
    CVE-2015-1214, CVE-2015-1215)

  - Multiple use-after-free errors exist in v8 bindings,
    DOM, GIF decoder, web databases, and service workers,
    which allow arbitrary code execution. (CVE-2015-1216,
    CVE-2015-1218, CVE-2015-1220, CVE-2015-1221,
    CVE-2015-1222, CVE-2015-1223)

  - Multiple type confusion errors exist in v8 bindings that
    allow arbitrary code execution. (CVE-2015-1217,
    CVE-2015-1230)

  - An integer overflow error exists in the WebGL that
    allows arbitrary code execution. (CVE-2015-1219)

  - Multiple out-of-bounds read errors exist in vpxdecoder
    and pdfium that allow unauthorized access to
    information. (CVE-2015-1224, CVE-2015-1225)

  - A validation error exists in the debugger.
    (CVE-2015-1226)

  - Multiple uninitialized value errors exist in blink and
    rendering. (CVE-2015-1227, CVE-2015-1228)

  - A cookie-injection vulnerability exists due to a failure
    to properly handle a 407 HTTP status code accompanied by
    a Set-Cookie header. (CVE-2015-1229)

  - Multiple, unspecified errors exist that allow remote
    attackers to cause a denial of service condition.
    (CVE-2015-1231)

  - An out-of-bounds write flaw exists due to an array index
    error in the DispatchSendMidiData() function that occurs
    when handling a port index supplied by a renderer. A
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2015-1232)

  - A spoofing vulnerability exists due to improper
    interaction between the '1993 search' features and
    restore-from-disk RELOAD transitions when Instant
    Extended mode is used. A remote attacker can exploit
    this to spoof the address bar for a search-results page.
    (CVE-2015-2239)");
  # http://googlechromereleases.blogspot.com/2015/03/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbe2503e");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 41.0.2272.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"in_the_news", value:"true");

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

google_chrome_check_version(fix:'41.0.2272.76', severity:SECURITY_HOLE);
