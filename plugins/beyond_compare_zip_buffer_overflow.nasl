#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46242);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/03/16 10:54:37 $");

  script_bugtraq_id(39907);

  script_name(english:"Beyond Compare Zip File Buffer Overflow");
  script_summary(english:"Checks version of Beyond Compare");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by 
a buffer overflow vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Beyond Compare installed on the remote Windows host is 
earlier than 3.1.11.  Such versions are potentially affected by a 
buffer overflow vulnerability when handling zip files with an overly 
large filename.  An attacker, exploiting this flaw, could potentially
execute arbitrary code on the remote host subject to the privileges of
the user running the application.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ad65be8");
  script_set_attribute(attribute:"solution", value:"Upgrade to Beyond Compare 3.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/06");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("beyond_compare_detect.nasl");
  script_require_keys("SMB/Beyond Compare/Version");

  exit(0);
}

include("global_settings.inc");

version = get_kb_item("SMB/Beyond Compare/Version");
if (isnull(version)) exit(1, "The 'SMB/Beyond Compare/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 3 ||
  (
    ver[0] == 3 &&
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 11)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.1.11\n';

    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected because Beyond Compare "+version+" is installed.");
