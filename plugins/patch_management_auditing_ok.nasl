#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( NASL_LEVEL < 3000 ) exit(0);

if (description)
{
  script_id(64295);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/30 15:38:55 $");

  script_name(english:"Patch Management Auditing Satisfied");
  script_summary(english:"Report when all patch management is up-to-date");

  script_set_attribute(attribute:"synopsis", value:
"This plugin reports when all patch management solutions correspond 
with one another.");
  script_set_attribute(attribute:"description", value:
"This plugin will report that all vulnerabilities correspond using the 
available patch management solutions and/or Nessus.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("patch_management_auditing.nasl");
  script_require_keys("patch_management/no/conflicts");

  exit(0);
}

include("misc_func.inc");

tool_report = get_kb_item_or_exit("patch_management/no/conflicts");

tool_list = split(tool_report, sep:",", keep:FALSE);

report = '\nAvailable patch management tools\n';
foreach tool (tool_list)
{
  report += "  " + tool+ '\n';
}

security_note(port:0 ,extra:report);
