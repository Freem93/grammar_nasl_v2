#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59846);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2012-0897");
  script_bugtraq_id(51426);
  script_osvdb_id(78333);

  script_name(english:"IrfanView JPEG-2000 Plugin Remote Stack-based Buffer Overflow");
  script_summary(english:"Checks version of JPEG2000.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by a 
stack-based buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the IrfanView JPEG-2000 plugin (JPEG2000.dll) was found
to be less than 4.33.  Such versions are affected by a stack-based
buffer overflow vulnerability that can be triggered by tricking users
into opening a .JP2 file with a specially crafted Quantization Default
section.  Successful exploitation may allow arbitrary code to be
executed on the affected host subject to the privileges of the user."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.irfanview.com/plugins.htm");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the JPEG-2000 plugin to version 4.3.3.0 (4.33) or higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Irfanview JPEG2000 jp2 Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date",value:"2012/01/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/05");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

plugin = "JPEG2000.dll";
fix = '4.3.3.0';

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
      '\n  Fixed version     : ' + fix + ' (4.33)\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, plugin_version);

