#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72397);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2013-3481");
  script_bugtraq_id(60236);
  script_osvdb_id(93751);

  script_name(english:"Artweaver 3.x < 3.1.5 JPG File Handling Stack-based Buffer Overflow");
  script_summary(english:"Checks Artweaver version");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a stack-based buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Artweaver 3.x prior to version 3.1.5.
It is, therefore, affected by an error related to handling JPG image
files that could allow stack-based buffer overflows.");
  script_set_attribute(attribute:"see_also", value:"http://forum.artweaver.de/viewtopic.php?f=5&t=2247");
  script_set_attribute(attribute:"see_also", value:"http://forum.artweaver.de/viewtopic.php?f=5&t=2248");
  script_set_attribute(attribute:"solution", value:"Upgrade to Artweaver 3.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:b-e-soft:artweaver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("artweaver_installed.nbin");
  script_require_keys("SMB/Artweaver/Installed");
  exit(0);

}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Artweaver/Installed");
installs = get_kb_list_or_exit("SMB/Artweaver/*/Version");
kb_entry = branch(keys(installs));
kb_base = kb_entry - "/Version";

version = get_kb_item_or_exit(kb_entry);
path    = get_kb_item_or_exit(kb_base + "/Path");
flavor  = get_kb_item(kb_base + "/Flavor");

if (isnull(flavor)) flavor = '';
else flavor = ' ' + flavor;

# Not 3.x
if (version !~ "^3($|[^0-9])") audit(AUDIT_NOT_INST, "Artweaver 3.x");

# Not granular enough
if (version =~ "^3(\.1)?$") audit(AUDIT_VER_NOT_GRANULAR, "Artweaver" + flavor, version);

if (ver_compare(ver:version, fix:'3.1.5', strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report += '\n  Product           : Artweaver' + flavor +
              '\n  Path              : ' + path +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 3.1.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Artweaver" + flavor, version, path);
