#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74369);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/14 15:47:37 $");

  script_cve_id("CVE-2013-1571");
  script_bugtraq_id(60634);
  script_osvdb_id(94372);
  script_xref(name:"CERT", value:"225657");

  script_name(english:"IBM Tivoli Directory Server 6.0.x / 6.1 < 6.1.0.58 / 6.2 < 6.2.0.33 / 6.3 < 6.3.0.25 Javadoc Frame Injection");
  script_summary(english:"Checks the version of Tivoli Directory Server.");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Tivoli Directory Server is affected by a frame
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM Tivoli Directory
Server on the remote host is 6.0.x or 6.1 < 6.1.0.58 / 6.2 < 6.2.0.33
/ 6.3 < 6.3.0.25. It is, therefore, affected by an error related to
the included Java version and input-validation that allows an attacker
to inject HTML frames into documents created by Javadoc.");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21642915");
  # 6.1.x fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24035907");
  # 6.2.x fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24035908");
  # 6.3.x fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24035909");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.1.0.58-ISS-ITDS-IF0058
  - 6.2.0.33-ISS-ITDS-IF0033
  - 6.3.0.25-ISS-ITDS-IF0025");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
#   6.0 and 6.1 branch : 6.1.0.58
#   6.2 branch : 6.2.0.33
#   6.3 branch : 6.3.0.25
if (version =~ '^6\\.')
{
  if (version =~ '^6\\.[01]\\.' && ver_compare(ver:version, fix:'6.1.0.58') == -1)
  {
    fixed = '6.1.0.58';
    patch = '6.1.0.58-ISS-ITDS-IF0058';
  }
  else if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.0.33') == -1)
  {
    fixed = '6.2.0.33';
    patch = '6.2.0.33-ISS-ITDS-IF0033';
  }
  else if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.0.25') == -1)
  {
    fixed = '6.3.0.25';
    patch = '6.3.0.25-ISS-ITDS-IF0025';
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
