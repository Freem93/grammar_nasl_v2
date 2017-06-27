#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77747);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2013-6663",
    "CVE-2014-4363",
    "CVE-2014-4409",
    "CVE-2014-4410",
    "CVE-2014-4411",
    "CVE-2014-4412",
    "CVE-2014-4413",
    "CVE-2014-4414",
    "CVE-2014-4415"
  );
  script_bugtraq_id(
    69881,
    69909,
    69937,
    69966,
    69970,
    69973,
    69974,
    69975,
    69976,
    69984
  );
  script_osvdb_id(
    103939,
    111652,
    111653,
    111654,
    111655,
    111656,
    111657,
    111662,
    111663
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-09-17-4");

  script_name(english:"Mac OS X : Apple Safari < 6.2 / 7.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is a
version prior to 6.2 or 7.1. It is, therefore, affected by the
following vulnerabilities :

  - An error exists related to saved passwords and the
    incorrect automatic filling of HTML forms. A remote
    attacker can exploit this to obtain sensitive
    information. (CVE-2014-4363)

  - Multiple memory corruption errors exist related to
    the included version of WebKit that can allow
    application crashes or arbitrary code execution.
    (CVE-2013-6663, CVE-2014-4410, CVE-2014-4411,
    CVE-2014-4412, CVE-2014-4413, CVE-2014-4414,
    CVE-2014-4415)

  - An error exists related to HTML5 application cache
    data handling and the included version of WebKit that
    allows the disclosure of sensitive information from
    private browsing sessions. (CVE-2014-4409)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6440");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.2 / 7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.[89]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8 / 10.9");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if ("10.8" >< os) fixed_version = "6.2";
else fixed_version = "7.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
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
