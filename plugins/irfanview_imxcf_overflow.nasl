#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63303);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/12/20 11:47:01 $");

  script_bugtraq_id(56901);
  script_osvdb_id(88422);
  script_xref(name:"EDB-ID", value:"23288");

  script_name(english:"IrfanView ImXCF.dll XCF File Handling Overflow");
  script_summary(english:"Checks version of ImXCF.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by a
stack-based buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:

"The version of the XCF plugin (ImXCF.dll) for IrfanView is earlier than
1.8.0.1314.  As such, it reportedly is affected by a stack-based buffer
overflow caused by insufficient validation when processing XCF files. 
An attacker could exploit this vulnerability to execute arbitrary code
by tricking a user into opening a specially crafted XCF file."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/plugins.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade the XCF plugin to version 1.8.0.1314 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = 'SMB/IrfanView/';
path = get_kb_item_or_exit(kb_base + 'Path');

plugin = "ImXCF.dll";
plugin_version = get_kb_item_or_exit(kb_base + 'Plugin_Version/' + plugin);

file = path + "\Plugins\" + plugin;
appname = "IrfanView XCF plugin";

fix = '1.8.0.1314';
if (ver_compare(ver:plugin_version, fix:fix) == -1)
{
  port = get_kb_item('SMB/transport');
  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + file +
      '\n  Installed version : ' + plugin_version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, plugin_version, path);
