#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66256);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/13 20:51:06 $");

  script_cve_id("CVE-2013-0556");
  script_osvdb_id(92933);

  script_name(english:"IBM Tivoli Directory Server 6.2 < 6.2.0.29 / 6.3 < 6.3.0.21 SSL / TLS DoS");
  script_summary(english:"Checks the version of Tivoli Directory Server.");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Tivoli Directory Server is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM Tivoli Directory
Server on the remote host is 6.2.x prior to 6.2.0.29 or 6.3.x prior to
6.3.0.21. It is, therefore, affected by a denial of service
vulnerability. It is possible for a connection to fail to time-out
while waiting for incoming data from the client on an SSL/TLS
connection.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ssl_tls_denial_of_service_vulnerability_in_ibm_tivoli_directory_server5?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f258fb4c");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21631687");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.2.0.29-ISS-ITDS-IF0029
  - 6.3.0.21-ISS-ITDS-IF0021");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
#   6.2 branch : 6.2.0.29
#   6.3 branch : 6.3.0.21
if (version =~ '^6\\.')
{
  if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.0.29') == -1)
  {
    fixed = '6.2.0.29';
    patch = '6.2.0.29-ISS-ITDS-IF0029';
  }
  else if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.0.21') == -1)
  {
    fixed = '6.3.0.21';
    patch = '6.3.0.21-ISS-ITDS-IF0021';
  }
}

if (isnull(fixed))
  audit(AUDIT_INST_PATH_NOT_VULN, 'IBM Tivoli Directory Server', version, path);

port = get_kb_item('SMB/transport');
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
