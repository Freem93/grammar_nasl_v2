#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78774);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/31 20:04:37 $");

  script_cve_id(
    "CVE-2013-1739",
    "CVE-2013-1740",
    "CVE-2013-5605",
    "CVE-2013-5606",
    "CVE-2014-1490",
    "CVE-2014-1491",
    "CVE-2014-1492"
  );
  script_bugtraq_id(
    62966,
    63737,
    63738,
    64944,
    65332,
    65335,
    66356
  );
  script_osvdb_id(
    98402,
    99746,
    99747,
    102170,
    102876,
    102877,
    104708
  );

  script_name(english:"Oracle OpenSSO Agent Multiple Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the version and patch number.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle OpenSSO agent installed on the remote host is missing a
vendor-supplied update. It is, therefore, affected by multiple
vulnerabilities in the bundled Mozilla Network Security Services, the
most serious of which can allow remote code execution.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:opensso");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_opensso_agent_installed.nbin");
  script_require_keys("installed_sw/Oracle OpenSSO Agent");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "Oracle OpenSSO Agent";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
ver  = install['version'];
path = install['path'];

fix = '3.0-05';

# OpenSSO Agent versions are in the format of 'major.minor-patch'
# Only version 3.0-04 is specified in the advisory as vulnerable
if (ver == "3.0-04")
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
