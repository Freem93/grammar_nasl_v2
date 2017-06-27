#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77201);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/03 13:25:44 $");

  script_cve_id(
    "CVE-2014-1384",
    "CVE-2014-1385",
    "CVE-2014-1386",
    "CVE-2014-1387",
    "CVE-2014-1388",
    "CVE-2014-1389",
    "CVE-2014-1390"
  );
  script_bugtraq_id(69223);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-08-13-1");

  script_name(english:"Mac OS X : Apple Safari < 6.1.6 / 7.0.6 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is a
version prior to 6.1.6 or 7.0.6. It is, therefore, affected by
multiple memory corruption vulnerabilities that exist in WebKit that
could lead to unexpected program termination or arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6367");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Aug/81");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.1.6 / 7.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/14");

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

if ("10.7" >< os || "10.8" >< os) fixed_version = "6.1.6";
else fixed_version = "7.0.6";

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
