#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72394);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/02 10:44:39 $");

  script_cve_id("CVE-2013-3944", "CVE-2013-3945", "CVE-2013-3946");
  script_bugtraq_id(64385, 64387, 64389);
  script_osvdb_id(101061, 101062, 101063);

  script_name(english:"IrfanView MrSID Plugin < 4.37 Multiple Buffer Overflows");
  script_summary(english:"Checks file version of MrSID.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote host is affected by multiple buffer
overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the IrfanView MrSID plugin (MrSID.dll) installed on the
remote Windows host is a version prior to 4.37.  It is, therefore,
affected by multiple buffer overflow vulnerabilities :

  - A stack-based buffer overflow exists due to improper
    validation of the 'IMAGE' tag. (CVE-2013-3944)

  - A heap-based buffer overflow exists due to improper
    validation of the 'nband' tag. (CVE-2013-3945)

  - An integer overflow exists due to improper validation
    of the 'levels' header, which could lead to a heap-based
    buffer overflow. (CVE-2013-3946)

An attacker can exploit these issues by sending a specially crafted SID
file, which could result in a denial of service or arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/54444/");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/plugins.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/main_history.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade the MrSID plugin to version 4.3.7.0 (4.37) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "IrfanView MrSID plugin";
plugin = "MrSID.dll";
fix = '4.3.7.0';

kb_base = 'SMB/IrfanView/';
path = get_kb_item_or_exit(kb_base + 'Path');

path += "\Plugins\" + plugin;
plugin_version = get_kb_item_or_exit(kb_base + 'Plugin_Version/' + plugin);

if (ver_compare(ver:plugin_version, fix:fix) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + plugin_version +
      '\n  Fixed version     : ' + fix + ' (4.37)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, plugin_version);
