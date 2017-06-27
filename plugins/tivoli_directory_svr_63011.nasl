#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58814);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/14 15:47:37 $");

  script_cve_id("CVE-2012-0726", "CVE-2012-0743");
  script_bugtraq_id(53043);
  script_osvdb_id(81356, 81357);

  script_name(english:"IBM Tivoli Directory Server < 6.1.0.47 / 6.2.0.22 / 6.3.0.11 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of Tivoli Directory Server.");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Tivoli Directory Server contains multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM Tivoli Directory
Server on the remote host is prior to 6.1.0.47 / 6.2.0.22 / 6.3.0.11. 
It is, therefore, affected by one or more of the following
vulnerabilities :

  - A custom LDAP client can be created which causes IBM 
    Tivoli Directory Server to crash by sending a malformed
    paged search request. (IO15707, IO16001, IO16002)

  - In the default Tivoli Directory Server environment, with
    TLS enabled, the NULL-MD5, and NULL-SHA ciphers are
    enabled by default. (IO16035, IO16036, IOO15761)");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_tivoli_directory_server_use_of_null_ciphers_in_default_transport_layer_security_configuration_would_result_in_unencrypted_communications_cve_2012_07261?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1609f9e3");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_tivoli_directory_server_paged_search_may_cause_denial_of_service_may_crash_if_paged_searches_are_enabled_cve_2012_07435?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b26c4617");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21591267");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21591272");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.1.0.47-ISS-ITDS-IF0047
  - 6.2.0.22-ISS-ITDS-IF0022
  - 6.3.0.11-ISS-ITDS-IF0011");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_directory_svr_installed.nasl");
  script_require_keys("installed_sw/IBM Security Directory Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app = "IBM Security Directory Server";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'];

fixed = NULL;
patch = NULL;

# Determine the proper fix given the version number.
#   6.1 branch : 6.1.0.47
#   6.2 branch : 6.2.0.22
#   6.3 branch : 6.3.0.11
if (version =~ '^6\\.')
{
  if (version =~ '^6\\.1\\.' && ver_compare(ver:version, fix:'6.1.0.47') == -1)
  {
    fixed = '6.1.0.47';
    patch = '6.1.0.47-ISS-ITDS-IF0047';
  }
  else if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.0.22') == -1)
  {
    fixed = '6.2.0.22';
    patch = '6.2.0.22-ISS-ITDS-IF0022';
  }
  else if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.0.11') == -1)
  {
    fixed = '6.3.0.11';
    patch = '6.3.0.11-ISS-ITDS-IF0011';
  }
}

if (isnull(fixed))
  audit(AUDIT_INST_PATH_NOT_VULN, 'IBM Tivoli Directory Server', version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n' +
    '\n  Install ' + patch  + ' to update installation.' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
