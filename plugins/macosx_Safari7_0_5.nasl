#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76316);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/03 13:25:44 $");

  script_cve_id(
    "CVE-2014-1325",
    "CVE-2014-1340",
    "CVE-2014-1345",
    "CVE-2014-1362",
    "CVE-2014-1363",
    "CVE-2014-1364",
    "CVE-2014-1365",
    "CVE-2014-1366",
    "CVE-2014-1367",
    "CVE-2014-1368",
    "CVE-2014-1369",
    "CVE-2014-1382"
  );
  script_bugtraq_id(68271, 68275, 68329);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-06-30-1");

  script_name(english:"Mac OS X : Apple Safari < 6.1.5 / 7.0.5 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is a
version prior to 6.1.5 or 7.0.5. It is, therefore, affected by the
following vulnerabilities :

  - Multiple memory corruption vulnerabilities exist in
    WebKit that could lead to unexpected program
    termination or arbitrary code execution.
    (CVE-2014-1325, CVE-2014-1340, CVE-2014-1362,
    CVE-2014-1363, CVE-2014-1364, CVE-2014-1365,
    CVE-2014-1366, CVE-2014-1367, CVE-2014-1368,
    CVE-2014-1382)

  - An error exists in WebKit related to domains in URLs
    and encoding that could allow spoofing attacks.
    (CVE-2014-1345)

  - An error exists in WebKit related to handling URLs
    being dragged between windows that could allow
    disclosure of local file content. (CVE-2014-1369)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6293");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532599/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.1.5 / 7.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.[7-9]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8 / 10.9");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if ("10.7" >< os || "10.8" >< os) fixed_version = "6.1.5";
else fixed_version = "7.0.5";

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
