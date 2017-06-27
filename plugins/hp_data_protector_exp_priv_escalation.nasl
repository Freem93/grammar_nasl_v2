#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38792);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/16 17:29:48 $");
  
  script_cve_id("CVE-2009-0714");
  script_bugtraq_id(34955);
  script_osvdb_id(54509);
  script_xref(name:"EDB-ID", value:"9006");
  script_xref(name:"EDB-ID", value:"9007");
  script_xref(name:"Secunia", value:"35084");

  script_name(english:"HP Data Protector Express Crafted Traffic Remote Memory Disclosure");
  script_summary(english:"Checks version of dpwinsdr.exe");
 
  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Windows host contains an application that is affected by a
local privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"HP Data Protector Express is installed on the remote host.  The
installed version of the software is affected by an unspecified local
privilege escalation vulnerability.  A local attacker could exploit
this vulnerability to trigger a denial of service condition or execute
arbitrary code with system level privileges. According to reports,
this flaw could also be triggered remotely by exploiting a memory 
leak vulnerability, see references for more information."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://ivizsecurity.com/security-advisory-iviz-sr-09002.html"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01697543
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?bbd5cf40"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/503482"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to HP Data Protector Express Single Server Edition version
3.5 SP2 build 47065 / 4.0 SP1 build 46537 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/15");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/05/13");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("hp_data_protector_exp_installed.nasl");
  script_require_keys("SMB/HP Data Protector Express/Path", "SMB/HP Data Protector Express/Version", "SMB/HP Data Protector Express/Build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/HP Data Protector Express/Path');
version = get_kb_item_or_exit('SMB/HP Data Protector Express/Version');
build = get_kb_item_or_exit('SMB/HP Data Protector Express/Build');

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;
if ((ver[0] == 3 && ver[1] < 50) ||
    (ver[0] == 3 && ver[1] == 50 && build < 47065)) fix = '3.50 build 47065';
else if (ver[0] == 4 && ver[1] == 0 && build < 46537) fix = '4.0 buid 46537';

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' +version + ' build ' + build +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:get_kb_item('SMB/transport'));
  }
  else security_warning(port:get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The HP Data Protector Express '+version+' Build '+build+' install in '+path+' is not affected.');
