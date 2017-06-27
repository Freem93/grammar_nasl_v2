#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65700);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id("CVE-2012-4284");
  script_bugtraq_id(55002);
  script_osvdb_id(84709);
  script_xref(name:"EDB-ID", value:"20485");

  script_name(english:"Viscosity ViscosityHelper Symlink Attack Local Privilege Escalation");
  script_summary(english:"Checks version of Viscosity");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by a privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Viscosity VPN client installed that
has a path name validation flaw in the setuid-set ViscosityHelper
binary.  This flaw can be exploited to execute arbitrary code with root
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.sparklabs.com/viscosity/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Viscosity 1.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Viscosity setuid-set ViscosityHelper Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sparklabs:viscosity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_viscosity_installed.nasl");
  script_require_keys("MacOSX/Viscosity/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Viscosity";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

# ensure only numerical portion of string is used in check
item = eregmatch(pattern:"^([0-9.]+)", string:version);
if (isnull(item)) exit(1, "Unable to parse version string.");

fix = "1.4.2";
if (ver_compare(ver:item[1], fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Viscosity", version, path);
