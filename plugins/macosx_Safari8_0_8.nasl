#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85446);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id(
    "CVE-2015-3729",
    "CVE-2015-3730",
    "CVE-2015-3731",
    "CVE-2015-3732",
    "CVE-2015-3733",
    "CVE-2015-3734",
    "CVE-2015-3735",
    "CVE-2015-3736",
    "CVE-2015-3737",
    "CVE-2015-3738",
    "CVE-2015-3739",
    "CVE-2015-3740",
    "CVE-2015-3741",
    "CVE-2015-3742",
    "CVE-2015-3743",
    "CVE-2015-3744",
    "CVE-2015-3745",
    "CVE-2015-3746",
    "CVE-2015-3747",
    "CVE-2015-3748",
    "CVE-2015-3749",
    "CVE-2015-3750",
    "CVE-2015-3751",
    "CVE-2015-3752",
    "CVE-2015-3753",
    "CVE-2015-3754",
    "CVE-2015-3755"
  );
  script_bugtraq_id(
    76338,
    76339,
    76341,
    76342,
    76344
  );
  script_osvdb_id(
    126104,
    126105,
    126106,
    126107,
    126108,
    126109,
    126110,
    126111,
    126112,
    126113,
    126114,
    126115,
    126116,
    126117,
    126118,
    126119,
    126120,
    126121,
    126122,
    126123,
    126124,
    126125,
    126126,
    126127,
    126128,
    126129,
    126130
  );

  script_name(english:"Mac OS X : Apple Safari < 6.2.8 / 7.1.8 / 8.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The web browser installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 6.2.8 / 7.1.8 / 8.0.8. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified flaw exists that allows an attacker to
    spoof UI elements by using crafted web pages.
    (CVE-2015-3729)

  - Multiple memory corruption flaws exist in WebKit due
    to improper validation of user-supplied input. An
    attacker can exploit these, by using a crafted web page,
    to execute arbitrary code. (CVE-2015-3730, CVE-2015-3731
    CVE-2015-3732, CVE-2015-3733, CVE-2015-3734,
    CVE-2015-3735, CVE-2015-3736, CVE-2015-3737,
    CVE-2015-3738, CVE-2015-3739, CVE-2015-3740,
    CVE-2015-3741, CVE-2015-3742, CVE-2015-3743,
    CVE-2015-3744, CVE-2015-3745, CVE-2015-3746,
    CVE-2015-3747, CVE-2015-3748, CVE-2015-3749)

  - A security policy bypass vulnerability exists in WebKit
    related to handling Content Security Policy report
    requests. An attacker can exploit this to bypass the
    HTTP Strict Transport Security policy. (CVE-2015-3750)

  - A security policy bypass vulnerability exists in WebKit
    that allows websites to use video controls to load
    images nested in object elements in violation of Content
    Security Policy directives. (CVE-2015-3751)

  - An information disclosure vulnerability exists in WebKit
    related to how cookies are added to Content Security
    Policy report requests, which results in cookies being
    exposed to cross-origin requests. Also, cookies set
    during regular browsing are sent during private
    browsing. (CVE-2015-3752)

  - An information disclosure vulnerability exists in the
    WebKit Canvas component when images are called using
    URLs that redirect to a data:image resource. An
    attacker, using a malicious website, can exploit this to
    disclose image data cross-origin. (CVE-2015-3753)

  - An information disclosure vulnerability exists in WebKit
    page loading where the caching of HTTP authentication
    credentials entered in private browsing mode were carried
    over into regular browsing, resulting in a user's private
    browsing history being exposed. (CVE-2015-3754)

  - A flaw in the WebKit process model allows a malicious
    website to display an arbitrary URL, which can allow
    user interface spoofing. (CVE-2015-3755)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205033");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari 6.2.8 / 7.1.8 / 8.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.([89]|10)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8 / 10.9 / 10.10");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);
fixed_version = NULL;

if ("10.8" >< os)
  fixed_version = "6.2.8";
else if ("10.9" >< os)
  fixed_version = "7.1.8";
else
  fixed_version = "8.0.8";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
