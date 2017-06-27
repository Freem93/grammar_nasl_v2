#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74024);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id("CVE-2014-0513");
  script_bugtraq_id(67359);
  script_osvdb_id(106902);
  script_xref(name:"IAVB", value:"2014-B-0054");

  script_name(english:"Adobe Illustrator CS6 Stack Overflow (APSB14-11)");
  script_summary(english:"Checks version of Adobe Illustrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by a stack
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Illustrator CS6
16.0.3 / 16.2.0 or earlier. It is, therefore, reportedly affected by a
stack overflow vulnerability that could allow code execution.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb14-11.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Illustrator CS6 16.0.5 / 16.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Adobe Illustrator";

version = get_kb_item_or_exit("SMB/Adobe Illustrator/version");
path = get_kb_item_or_exit("SMB/Adobe Illustrator/path");
prod = get_kb_item_or_exit("SMB/Adobe Illustrator/product");

vuln = 0;

ver = split(version, sep:'.', keep:FALSE);

if (
    ver[0] == 16 &&
    (
      (ver[1] == 0 && ver[2] <= 3) ||
      (ver[1] == 2 && ver[2] < 0)
    )
) vuln++;

if (ver[0] == 16 && ver[1] == 2 && ver[2] == 0)
{
  timestamp = get_kb_item_or_exit("SMB/Adobe Illustrator/timestamp");
  arch = get_kb_item_or_exit("SMB/ARCH");

  if('x86' >< arch && timestamp >= 1393320637)
    exit(0, "The " + appname + " version " + version + " install under " + path + " has the update applied.");
  else vuln++;

  if('x64' >< arch && timestamp >= 1393326542)
    exit(0, "The " + appname + " version " + version + " install under " + path + " has the update applied.");
  else vuln++;
}

if (vuln > 0)
{
  if (ver[0] == 16 && ver[1] == 0) fix = '16.0.5';
  else fix = '16.2.2';

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
