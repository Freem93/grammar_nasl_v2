#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73733);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/08 22:17:48 $");

  script_cve_id("CVE-2014-2411");
  script_bugtraq_id(66829);
  script_osvdb_id(105840);

  script_name(english:"Oracle Identity Analytics / Sun Role Manager Unspecified Remote Vulnerability (April 2014 CPU)");
  script_summary(english:"Checks for April 2014 critical patch update");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Identity Analytics (formerly known as Sun Role
Manager) install is affected by an unspecified vulnerability that can
be exploited by remote, authenticated attackers.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:sun_role_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_identity_analytics_detect.nbin");
  script_require_keys("www/oracle_identity_analytics");
  script_require_ports("Services/www", 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Oracle Identity Analytics";

port = get_http_port(default:7001);

install = get_install_from_kb(appname:"oracle_identity_analytics", port:port, exit_on_fail:TRUE);

dir = install['dir'];
version = install['ver'];

orig_ver_str = version;

install_url = build_url(port: port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Oracle Identity Analytics", install_url);

# convert to something we can use in ver_compare
# e.g.
# 11.1.1.5.7 (Build 20140207_2_12722) -> 11.1.1.5.7.20140207
# 5.0.3 (Build 20140207_2_12723) -> 5.0.3.20140207
# The build date is specific enough for our checks
version = str_replace(find:" (Build ", replace:".", string:version);
item = eregmatch(pattern:"^([0-9.]+)($|[^0-9.])", string:version);
if (isnull(item)) exit(1, "Failed to parse the version string for the Oracle Identity Analytics install at "+install_url+".");

version = item[1];

report = '';

# OIA 11.1.1.5.x and Sun Role Manager 5.0.x are listed as affected
if (version =~ "^11\.1\.1\.5($|\.)")
{
  if (ver_compare(ver:version, fix:"11.1.1.5.7", strict:FALSE) == -1)
  {
    report = '\n  Installed version : ' + orig_ver_str +
             '\n  Fixed version     : 11.1.1.5.7' +
             '\n  Required patch    : 18182466\n';
  }
}
else if (version =~ "^5($|\.0($|\.))")
{
  appname = "Sun Role Manager"; # more accurate application name
  if (ver_compare(ver:version, fix:"5.0.3.20140207", strict:FALSE) == -1)
  {
    report = '\n  Installed version : ' + orig_ver_str +
             '\n  Fixed version     : 5.0.3.3 (5.0.3 Build 20140207)' +
             '\n  Required patch    : 18175969\n';
  }
}

if (report == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, orig_ver_str);

if (report_verbosity > 0) security_warning(extra:report, port:port);
else security_warning(port);
