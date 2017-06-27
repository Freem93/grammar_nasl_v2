#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94898);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id("CVE-2016-5995");
  script_bugtraq_id(93012);
  script_osvdb_id(144339, 144371, 144373);

  script_name(english:"IBM DB2 10.5 < Fix Pack 8 Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.5 running on
the remote host is prior to Fix Pack 8. It is, therefore, affected by
the following vulnerabilities :

  - A local privilege escalation vulnerability exists due to
    insecurely loading binaries planted in a location that a
    SETGID or SETUID binary would execute. A local attacker
    can exploit this, via a malicious binary, to gain root
    privileges. (CVE-2016-5995)

  - A denial of service vulnerability exists in the
    SQLNP_SCOPE_TRIAL() function due to improper handling of
    SQL statements. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 144371)

  - A denial of service vulnerability exists in the Query
    Compiler QGM due to improper handling of specific
    queries. An authenticated, remote attacker can exploit
    this, via a specially crafted query, to crash the
    database. (VulnDB 144373)");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21990061");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21633303#8");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 10.5 Fix Pack 8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "DB2 Server";
install  = get_single_install(app_name:app_name);
version  = install['version'];
path     = install['path'];
port     = 0;

# DB2 has an optional OpenSSH server that will run on 
# windows.  We need to exit out if we picked up the windows
# installation that way.
if ("linux" >!< tolower(install['platform']) && "aix" >!< tolower(install['platform']))
  audit(AUDIT_HOST_NOT, "Linux based operating system");

fixed = "10.5.0.8";

if (version =~ "^10\.5\." && ver_compare(ver:version, fix:fixed, strict:FALSE) <  0)
{
  report =
    '\n  Product           : ' + app_name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
