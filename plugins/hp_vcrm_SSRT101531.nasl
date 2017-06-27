#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77025);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"HP", value:"emr_na-c04262472");
  script_xref(name:"HP", value:"HPSBMU03020");
  script_xref(name:"HP", value:"SSRT101531");

  script_name(english:"HP Version Control Repository Manager (VCRM) Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks the version of the VCA package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP Version Control Repository Manager (VCRM) install
on the remote Windows host is version 7.2.0, 7.2.1, 7.2.2, 7.3.0, or
7.3.1. It is, therefore, affected by an information disclosure
vulnerability.

An out-of-bounds read error, known as the 'Heartbleed Bug', exists
related to handling TLS heartbeat extensions that could allow an
attacker to obtain sensitive information such as primary key material,
secondary key material, and other protected content.");
  script_set_attribute(attribute:"solution", value:"Upgrade to VCRM 7.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04262472
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cd9b7f9");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_repository_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_version_control_repo_manager_installed.nbin");
  script_require_keys("installed_sw/HP Version Control Repository Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "HP Version Control Repository Manager";
get_install_count(app_name:appname, exit_if_zero:TRUE);

# Only 1 install is possible at a time
installs = get_installs(app_name:appname);
if (installs[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, appname);
install = installs[1][0];

version = install['version'];
path = install['path'];

# Unknown version
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER,appname);

# These exact versions are vulnerable
if (
  version =~ "^7\.2\.[0-2]\." ||
  version =~ "^7\.3\.[0-1]\."
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.3.2' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
