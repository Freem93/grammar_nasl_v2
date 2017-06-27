#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53625);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/14 15:47:37 $");

  script_cve_id("CVE-2011-1206");
  script_bugtraq_id(47121);
  script_osvdb_id(72683);

  script_name(english:"IBM Tivoli Directory Server Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of Tivoli Directory Server.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of IBM Tivoli Directory Server installed on the remote
host contains multiple security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the installation of IBM Tivoli Directory
Server on the remote host is prior to 6.0.0.67, 6.1.0.40, 6.2.0.16, or
6.3.0.3. It is, therefore, affected by one or more of the following
vulnerabilities :

  - A malicious LDAP request can cause a buffer overrun in
    the server, allowing an unauthenticated, remote attacker
    to execute arbitrary code within Tivoli Directory
    Server's server process. This vulnerability has only
    been recreated on 32 bit platforms. (IO14010, IO14013,
    IO14028, IO14046, IO14045)

  - A security vulnerability has been identified in Tivoli
    Directory server. If the Server is configured to audit
    extended operations with 'Attributes sent on group
    evaluation extended operation' enabled
    (ibm-auditAttributesOnGroupEvalOp=TRUE), the audit
    entries for the group eval extended op will include
    unmasked values for sensitive data. (IO14023, IO14025,
    IO14028, IO14043, IO14044)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d3972f7");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-136/");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21496117");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21496086");
  script_set_attribute(
    attribute:"solution",
    value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.0.0.8-TIV-ITDS-IF0009
  - 6.1.0.5-TIV-ITDS-IF0003
  - 6.2.0.3-TIV-ITDS-IF0002
  - 6.3.0.0-TIV-ITDS-IF0003"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_directory_svr_installed.nasl");
  script_require_keys("installed_sw/IBM Security Directory Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "IBM Security Directory Server";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'];

fixed = NULL;
patch = NULL;

# Determine the proper fix given the version number.
#   6.0 branch : 6.0.0.67
#   6.1 branch : 6.1.0.40
#   6.2 branch : 6.2.0.16
#   6.3 branch : 6.3.0.3
if (version =~ '^6\\.')
{
  if (version =~ '^6\\.0\\.' && ver_compare(ver:version, fix:'6.0.0.67') == -1)
  {
    fixed = "6.0.0.67";
    patch = "6.0.0.8-TIV-ITDS-IF0009";
  }
  else if (version =~ '^6\\.1\\.' && ver_compare(ver:version, fix:'6.1.0.40') == -1)
  {
    fixed = "6.1.0.40";
    patch = "6.1.0.5-TIV-ITDS-IF0003";
  }
  else if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.0.16') == -1)
  {
    fixed = "6.2.0.16";
    patch = "6.2.0.3-TIV-ITDS-IF0002";
  }
  else if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.0.3') == -1)
  {
    fixed = "6.3.0.3";
    patch = "6.3.0.0-TIV-ITDS-IF0003";
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

  security_hole(port:port, extra:report);
}
else security_hole(port);
