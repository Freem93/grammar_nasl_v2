#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78678);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/07 21:05:39 $");

  script_cve_id(
    "CVE-2014-1391",
    "CVE-2014-4350",
    "CVE-2014-4351",
    "CVE-2014-4979"
  );
  script_bugtraq_id(68852, 69907, 69908, 70643);
  script_osvdb_id(109476, 111665, 111666, 113447);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-10-22-1");

  script_name(english:"QuickTime < 7.7.6 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the version of QuickTime on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple QuickTime installed on the remote Windows host is
prior to 7.7.6. It is, therefore, affected by the following
vulnerabilities :

  - A memory corruption flaw exists when handling specially
    crafted RLE encoded videos due to user-supplied input
    not being properly sanitized. (CVE-2014-1391)

  - A buffer overflow flaw exists when parsing specially
    crafted MIDI files due to user-supplied input not being
    properly validated. (CVE-2014-4350)

  - A buffer overflow flaw exists when parsing specially
    crafted M4A files due to user-supplied input not being
    properly validated. (CVE-2014-4351)

  - A memory corruption flaw exists in the mvhd atom when
    handling malformed version numbers and flags due to not
    properly sanitizing user-supplied input. (CVE-2014-4979)

Successful exploitation of these issues by a remote attacker can
result in program termination or arbitrary code execution, subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/kb/HT6493");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533790/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to QuickTime 7.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

fixed_version = "7.76.80.95";
fixed_version_ui = "7.7.6 (1680.95.31)";

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
