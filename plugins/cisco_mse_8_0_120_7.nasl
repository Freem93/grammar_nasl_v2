#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86912);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-4282", "CVE-2015-6316");
  script_bugtraq_id(77432, 77435);
  script_osvdb_id(129888, 129889);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv40504");
  script_xref(name:"IAVA", value:"2015-A-0283");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv40501");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-privmse");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-mse-cred");

  script_name(english:"Cisco MSE <= 8.0.120.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cisco MSE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco MSE version
installed on the remote host is prior to 8.0.120.7. It is, therefore,
affected by multiple vulnerabilities :

  - A local privilege escalation vulnerability exists due to
    the program using insecure permissions for binary files
    during its physical or virtual appliance installation
    procedure. A local attacker can exploit this, by writing
    to a file, to gain root privileges. (CVE-2015-4282)

  - A security bypass vulnerability exists due to the
    default configuration of sshd_config allowing logins by
    the 'oracle' account which has a hard-coded password. An
    unauthenticated, remote user can exploit this gain 
    privileged access to the system. (CVE-2015-6316)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-privmse
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5c1d42b");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-mse-cred
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2586918c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuv40501 and CSCuv40504. Alternatively, apply the workaround
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:mobility_services_engine");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_mse_installed.nbin");
  script_require_keys("installed_sw/Cisco MSE");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Cisco MSE";

install = get_single_install(
  app_name : app,
  exit_if_unknown_ver : TRUE
);

version = install["version"];
path = install["path"];

# Check granularity
if (version !~ "^[0-9.]+$") audit(AUDIT_VER_FORMAT, version);

cutoff = "8.0.120.7";
if (ver_compare(ver:version, fix:cutoff, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See vendor.' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
