#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46860);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2010-2308");
  script_bugtraq_id(40715);
  script_osvdb_id(65377);
  script_xref(name:"Secunia", value:"40085");

  script_name(english:"Sophos Anti-Virus SAVOnAccessFilter Local Privilege Escalation");
  script_summary(english:"Checks the product's version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Sophos Anti-Virus installation
on the remote Windows host is affected by a local privilege escalation
vulnerability.  A local attacker, exploiting this flaw, could execute
arbitrary code in kernel mode and thereby gain complete control of the
affected system.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jun/193");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/support/knowledgebase/article/111126.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sophos Anti-Virus version 7.6.20, 9.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("sophos_installed.nasl");
  script_require_keys("Antivirus/Sophos/installed", "Antivirus/Sophos/prod_ver");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Get the product version.
version = get_kb_item("Antivirus/Sophos/prod_ver");
if (!version) exit(1, "The 'Antivirus/Sophos/prod_ver' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("7.6.20", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
{
  if ((ver[i] < fix[i]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 7.6.20 / 9.x\n';
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(port:get_kb_item("SMB/transport"));
    exit(0);
  }
  else if ( ver[i] > fix[i]) break;
}
exit(0, "The remote host is not affected because Sophos Anti-Virus version "+version+" is installed.");
