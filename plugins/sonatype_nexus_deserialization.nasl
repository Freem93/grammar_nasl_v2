#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92467);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/21 15:27:33 $");

  script_osvdb_id(129952, 130424, 140288);
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Sonatype Nexus Repository Manager Java Object Deserialization RCE");
  script_summary(english:"Checks the version of the Nexus Repository Manager server.");

  script_set_attribute(attribute:"synopsis", value:
"The Nexus Repository Manager server running on the remote host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Sonatype Nexus Repository Manager server application running on
the remote host is affected by a remote code execution vulnerability
due to unsafe deserialize calls of unauthenticated Java objects to the
Apache Commons Collections (ACC) library. An unauthenticated, remote
attacker can exploit this, by sending specially crafted Java objects
to the HTTP interface, to execute arbitrary code on the target host.");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"see_also", value:"http://www.sonatype.org/advisories/archive/2016-06-20-Nexus/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sonatype Nexus Repository Manager version 2.11.2-01 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonatype:nexus");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("sonatype_nexus_detect.nbin");
  script_require_ports("Services/www", 8081);
  script_require_keys("installed_sw/Sonatype Nexus");

  exit(0);
}

include("global_settings.inc");
include("webapp_func.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

appname = 'Sonatype Nexus';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8081);
install = get_single_install(app_name:appname, port:port);
fixed = "2.11.2-01";

if (isnull(install["version"])) audit(AUDIT_UNKNOWN_APP_VER, appname);

# ver_compare doesn't do hyphens well.
normalized_version = str_replace(string:install["version"], find: "-", replace: ".");
normalized_fix = str_replace(string:fixed, find: "-", replace: ".");

if (ver_compare(ver:normalized_version, fix:normalized_fix, strict:FALSE) < 0)
{
  report = '\n  Installed version : ' + install["version"] +
           '\n  Fixed version     : ' + fixed + ' \n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname);
