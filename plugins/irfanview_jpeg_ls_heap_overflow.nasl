#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60037);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/07/19 19:20:54 $");

  script_cve_id("CVE-2012-3585");
  script_bugtraq_id(54244);
  script_osvdb_id(83633);
  script_xref(name:"EDB-ID", value:"19483");

  script_name(english:"IrfanView JLS Plugin JLS Compressed Image File Handling Overflow");
  script_summary(english:"Checks version of Jpeg_LS.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by a 
heap-based buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the IrfanView JLS plugin (Jpeg_LS.dll) library is
earlier than 0.6.4.1.  As such, it reportedly is affected by a heap-
based buffer overflow caused by insufficient validation when
processing compressed JLS images.  An attacker could exploit this
vulnerability to execute arbitrary code by tricking a user into
opening a specially crafted JLS file."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/plugins.htm");
  # http://www.reactionpenetrationtesting.co.uk/Irfanview-JLS-Heap-Overflow.html   
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9dd60a1");
  script_set_attribute(attribute:"solution", value:"Upgrade the JLS plugin to version 0.6.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

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

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

kb_base = 'SMB/IrfanView/';
path = get_kb_item_or_exit(kb_base + 'Path');

plugin = "Jpeg_LS.dll";
fix = '0.6.4.1';

path += "\Plugins\" + plugin;
plugin_version = get_kb_item_or_exit(kb_base + 'Plugin_Version/' + plugin);
appname = "IrfanView " + plugin + " plugin";

if (ver_compare(ver:plugin_version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + path +
      '\n  Installed version : ' + plugin_version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, plugin_version);
