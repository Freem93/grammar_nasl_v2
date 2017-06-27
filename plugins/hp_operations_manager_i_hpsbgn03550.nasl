#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89780);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/10 15:12:10 $");

  script_cve_id("CVE-2015-3269");
  script_bugtraq_id(76394);
  script_osvdb_id(126408);
  script_xref(name:"HP", value:"HPSBGN03550");
  script_xref(name:"HP", value:"SSRT102232");
  script_xref(name:"HP", value:"emr_na-c05026202");

  script_name(english:"HP Operations Manager i Apache Flex BlazeDS External Entity Injection Vulnerability");
  script_summary(english:"Checks for patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an external entity injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote HP Operations Manager i host is affected by an XML external
entity (XXE) vulnerability in the bundled version of Apache Flex
BlazeDS due to an incorrectly configured XML parser accepting XML
external entities from an untrusted source. A remote attacker can
exploit this, via a specially crafted XML file, to read and disclose
arbitrary files.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05026202
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbf88d2f");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_manager_i");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_operations_manager_i_installed.nbin");
  script_require_keys("installed_sw/HP Operations Manager i");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

global_var appname;
appname = "HP Operations Manager i";

function is_patched(version, patch, path)
{
  local_var item, ip_level, ip_fix;

  ip_fix = 2;
  if(version == "10.00") ip_fix = 3;

  if(isnull(patch))
    return version + ' IP ' + ip_fix;

  item = eregmatch(pattern:"^[0-9.]+ IP ([0-9]+)($|[^0-9])",
                   string:patch);

  if(isnull(item) || isnull(item[1]))
    exit(1, "Unable to parse patch information : '" + patch + "'");

  ip_level = int(item[1]);

  if(ip_fix < ip_level)
    return version + ' IP ' + ip_fix;

  return '';
}

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
patch   = install['Patch'];
path    = install['path'];

if(version !~ "^10\.0[01]$")
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

fix = is_patched(version:version, patch:patch, path:path);

if (fix != '')
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version;
  if(!isnull(patch)) report +=
    '\n  Installed patch   : ' + patch;
  report +=
    '\n  Fixed version     : ' + fix +
    '\n';

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
