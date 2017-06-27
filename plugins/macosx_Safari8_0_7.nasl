#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84491);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2015-3658",
    "CVE-2015-3659",
    "CVE-2015-3660",
    "CVE-2015-3727"
  );
  script_osvdb_id(
    123914,
    123917,
    123918,
    123964
  );

  script_name(english:"Mac OS X : Apple Safari < 6.2.7 / 7.1.7 / 8.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The web browser installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 6.2.7 / 7.1.7 / 8.0.7. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in WebKit Page Loading due to the Origin
    request header being preserved for cross-origin
    redirects. A remote attacker can exploit this, via a
    specially crafted web page, to circumvent cross-site
    request forgery (XSRF) protections. (CVE-2015-3658)

  - A flaw exists in the WebKit Storage's SQLite authorizer
    due to insufficient comparison. A remote attacker can
    exploit this, via a specially crafted web page, to
    invoke arbitrary SQL functions, resulting in a denial
    of service condition or executing arbitrary code.
    (CVE-2015-3659)

  - An information disclosure vulnerability exists in WebKit
    PDF due to improper restrictions, related to JavaScript
    execution, of links embedded in PDF files. A remote
    attacker can exploit this, via a specially crafted PDF
    file, to disclose sensitive information from the file
    system, including cookies. (CVE-2015-3660)

  - An information disclosure vulnerability exists in WebKit
    due to improper restrictions on renaming WebSQL tables.
    A remote attacker can exploit this, via a specially
    crafted website, to access WebSQL databases belonging to
    other websites. (CVE-2015-3727)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204950");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari 6.2.7 / 7.1.7 / 8.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
  fixed_version = "6.2.7";
else if ("10.9" >< os)
  fixed_version = "7.1.7";
else
  fixed_version = "8.0.7";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
