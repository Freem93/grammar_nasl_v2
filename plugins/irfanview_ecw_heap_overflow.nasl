#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59849);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/07/06 12:43:08 $");

  script_bugtraq_id(53744);
  script_osvdb_id(82576);
  script_xref(name:"EDB-ID", value:"18964");

  script_name(english:"IrfanView Formats Plugin ECW Plugin File Handling Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of NCSEcw.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by a 
heap-based buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the IrfanView Formats ECW plugin (NCSEcw.dll) was found
to be less than 4.34.  Such versions are affected by a heap-based
buffer overflow caused by insufficient validation when decompressing
ECW images.  An attacker could exploit this vulnerability to
execute arbitrary code by tricking a user into opening a specially
crafted .ecw file."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.irfanview.com/plugins.htm");
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?fca07084");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the Formats ECW plugin to version 3.1.0.350 (4.34) or higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/05/31");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/05/24");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/05");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

plugin = "Ecw\NCSEcw.dll";
fix = '3.1.0.350';

kb_base = 'SMB/IrfanView/';
appname = "IrfanView " + plugin + " plugin";
path = get_kb_item_or_exit(kb_base + 'Path');

path += "\Plugins\" + plugin;
plugin_version = get_kb_item_or_exit(kb_base + 'Plugin_Version/' + plugin);

if (ver_compare(ver:plugin_version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + plugin_version +
      '\n  Fixed version     : ' + fix + ' (4.34)\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, plugin_version);

