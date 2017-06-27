#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81600);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2014-7286");
  script_bugtraq_id(71727);
  script_osvdb_id(116082);

  script_name(english:"Symantec Deployment Solution AClient <= 6.9 Buffer Overflow");
  script_summary(english:"Checks the version of Symantec Deployment Solution AClient.");

  script_set_attribute(attribute:'synopsis', value:
"The remote host has an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:'description', value:
"The Symantec Deployment Solution AClient installed on the remote host
is version 6.9 or prior. It is, therefore, affected by a buffer
overflow vulnerability that is triggered when handling an IOCTL. A
local attacker can exploit this to gain elevated privileges.");
  script_set_attribute(attribute:'solution', value:"Disable AClient and use DAgent instead.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20141219_00
  script_set_attribute(attribute:'see_also', value:"http://www.nessus.org/u?1fb21246");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:deployment_solution");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("symantec_ds_client_service_detect.nbin");
  # script_dependencies("altiris_client_service_detect.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "installed_sw/Symantec Deployment Solution Client");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

windows_version = get_kb_item_or_exit("SMB/WindowsVersion");
if (windows_version !~ "^5\.[12]$") audit(AUDIT_OS_NOT, "Windows XP/2003");

app = "Symantec Deployment Solution Client";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
path    = install['path'];
client  = install['Client Type'];

port = get_kb_item('SMB/transport');
if (!port) port = 445;

# Version 6.9 and below are vulnerable
if ( client == "AClient" && ver_compare(ver:ver, fix:'6.9', strict:FALSE) <= 0 )
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Client type       : ' + client +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : See vendor advisory.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app + ' (' + client + ')', ver, path);
