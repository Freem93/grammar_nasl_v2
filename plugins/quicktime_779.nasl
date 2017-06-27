#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87848);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/19 17:53:34 $");

  script_cve_id(
    "CVE-2015-7085",
    "CVE-2015-7086",
    "CVE-2015-7087",
    "CVE-2015-7088",
    "CVE-2015-7089",
    "CVE-2015-7090",
    "CVE-2015-7091",
    "CVE-2015-7092",
    "CVE-2015-7117"
  );
  script_osvdb_id(
    132636,
    132637,
    132638,
    132639,
    132640,
    132641,
    132642,
    132643,
    132644
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-01-07-1");

  script_name(english:"Apple QuickTime < 7.7.9 Multiple RCE (Windows)");
  script_summary(english:"Checks the version of QuickTime on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple QuickTime installed on the remote Windows host is
prior to 7.7.9. It is, therefore, affected by multiple remote code
execution vulnerabilities due to improper validation of user-supplied
input. An unauthenticated, remote attacker can exploit these, via a
crafted movie file, to execute arbitrary code or cause a denial of
service through memory corruption.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205638");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple QuickTime version 7.7.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/QuickTime/";

version = get_kb_item_or_exit(kb_base+"Version");
path = get_kb_item_or_exit(kb_base+"Path");

version_ui = get_kb_item(kb_base+"Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "7.79.80.95";
fixed_version_ui = "7.7.9 (1680.95.84)";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_ui +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'QuickTime Player', version_report, path);
