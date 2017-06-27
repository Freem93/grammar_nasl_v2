#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91339);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id("CVE-2016-3427");
  script_osvdb_id(137303);
  script_xref(name:"VMSA", value:"2016-0005");

  script_name(english:"VMware VRealize Operations Manager 6.x Oracle JRE JMX Deserialization RCE (VMSA-2016-0005)");
  script_summary(english:"Looks for VMware VRealize 6.x installations.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware vRealize Operations Manager (vROps) 6.x host is
affected by a remote code execution vulnerability in the Oracle JRE
JMX component due to a flaw related to the deserialization of
authentication credentials. An unauthenticated, remote attacker can
exploit this to execute arbitrary code.

Note that only non-appliance versions of vRealize Operations Manager
are affected by the vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0005");
  script_set_attribute(attribute:"solution", value:
"Block the appropriate ports per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vrealize_operations");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_vrealize_operations_manager_webui_detect.nbin");
  script_require_ports("installed_sw/vRealize Operations Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

app  = "vRealize Operations Manager";

if(get_install_count(app_name:app) == 0)
  audit(AUDIT_NOT_INST, app);

port = get_http_port(default:443);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];

if (version !~ "^6($|\.)")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

# the mitigation is to firewall off the affected ports
# check to see if we can establish a connection to port 9004 or 9005 (these are common among all affected versions).
# if we can establish a connection, the remote host is likely vulnerable
vuln = FALSE;

soc = open_sock_tcp(9004);
port = 9004;

if(!soc)
{
  soc = open_sock_tcp(9005);
  port = 9005;
}

if(soc)
{
  vuln = TRUE;
  close(soc);
}

if(!vuln)
  exit(0, "Port 9004 and 9005 are not open on the remote host. Therefore, it is likely the mitigation has been applied or the host is an appliance.");

report = '\nVersion : ' + version + '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
