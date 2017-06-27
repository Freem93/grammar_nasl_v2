#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66784);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/04 16:08:05 $");

  script_cve_id("CVE-2013-3486");
  script_bugtraq_id(60232);
  script_osvdb_id(93753);

  script_name(english:"IrfanView FlashPix Plugin < 4.36 Summary Information Property Set Handling Integer Overflow");
  script_summary(english:"Checks version of Fpx.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the IrfanView FlashPix plugin (Fpx.dll) was found to be
earlier than 4.36.  As such, it is affected by an integer overflow error
within the 'Fpx.dll' module.  The 'Summary Information Property Set' is
not properly validated, which could result in a heap-based buffer
overflow, allowing an attacker to cause a denial of service or execute
arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/plugins.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade the FlashPix plugin to version 4.3.6.0 (4.36) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:flashpix_plugin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

plugin = "Fpx.dll";
fix = '4.3.6.0';

kb_base = 'SMB/IrfanView/';
appname = "IrfanView " + plugin + " plugin";
path = get_kb_item_or_exit(kb_base + 'Path');

path += "\Plugins\" + plugin;
plugin_version = get_kb_item_or_exit(kb_base + 'Plugin_Version/' + plugin);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (ver_compare(ver:plugin_version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + plugin_version +
      '\n  Fixed version     : ' + fix + ' (4.36)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, plugin_version);

