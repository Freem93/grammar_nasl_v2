#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77408);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2014-3524", "CVE-2014-3575");
  script_bugtraq_id(69351, 69354);
  script_osvdb_id(110266, 110267);

  script_name(english:"Apache OpenOffice < 4.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a
version prior to 4.1.1. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified flaw allows remote attackers to execute
    arbitrary commands via a specially crafted Calc
    spreadsheet. (CVE-2014-3524)

  - A flaw in the OLE preview generation allows a remote
    attacker to embed arbitrary data into documents via
    specially crafted OLE objects. (CVE-2014-3575)");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2014-3524.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2014-3575.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache OpenOffice version 4.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Apache OpenOffice";
build = get_kb_item_or_exit("SMB/OpenOffice/Build");
path  = get_kb_item("SMB/OpenOffice/Path");
version_ui = get_kb_item("SMB/OpenOffice/Version_UI");

matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
if (isnull(matches)) audit(AUDIT_VER_FAIL, app);

buildid = int(matches[2]);
if (buildid <= 9764)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.1.1 (411m6 / build 9775)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version_ui, path);
