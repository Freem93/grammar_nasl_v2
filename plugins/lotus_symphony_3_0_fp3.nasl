#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59036);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/05/10 01:35:42 $");

  script_cve_id(
    "CVE-2011-2884",
    "CVE-2011-2885",
    "CVE-2011-2886",
    "CVE-2011-2888",
    "CVE-2011-2893"
  );
  script_bugtraq_id(48936);
  script_osvdb_id(73988, 74159, 74160, 74165, 74166);

  script_name(english:"IBM Lotus Symphony < 3.0 Fix Pack 3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of IBM Lotus Symphony");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple vulnerabilities. "
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM Lotus Symphony was found to be less than 3.0 Fix
Pack 3.  Such versions are affected by multiple vulnerabilities:

  - Multiple unspecified vulnerabilities.
    (CVE-2011-2884)

  - Opening a .doc document with a user defined toolbar can 
    cause an application crash. (CVE-2011-2885)

  - Opening a .docx document with empty bullet styles for 
    parent bullets will cause an application crash. 
    (CVE-2011-2886)

  - Opening in DataPilot a large .xls file that contains an
    invalid 'Value' reference, modifying it, and then
    saving it will cause an application crash.
    (CVE-2011-2893)

  - The application freezes when opening a presentation that
    contains many complex graphics. (CVE-2011-2888)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8507824d");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to IBM Lotus Symphony 3.0 Fix Pack 3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_symphony");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("lotus_symphony_installed.nasl");
  script_require_keys("SMB/Lotus_Symphony/Installed");
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

appname = "Lotus Symphony";

kb_base = "SMB/Lotus_Symphony/";
port = get_kb_item("SMB/transport");

get_kb_item_or_exit(kb_base + "Installed");
version = get_kb_item_or_exit(kb_base + "Version");

# extract build timestamp
item = eregmatch(pattern:"([0-9]+)-([0-9]+)$", string:version);
if (isnull(item)) exit(1, "Error parsing the version string ("+version+").");

# date/time
dt = int(item[1]);
tm = int(item[2]);

if(
   dt < 20110707 ||
   (dt == 20110707 && tm < 1500)
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item(kb_base + "Path");
    ver_ui = get_kb_item(kb_base + "Version_UI");
    report = '\n  Path              : ' + path + 
             '\n  Installed version : ' + ver_ui +
             '\n  Fixed version     : 3.0 Fix Pack 3 (3.0.0.20110707-1500)\n';
   security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
