#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89925);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2016-0788",
    "CVE-2016-0789",
    "CVE-2016-0790",
    "CVE-2016-0791",
    "CVE-2016-0792"
  );
  script_osvdb_id(
    129952,
    130424,
    134991,
    135041,
    135042,
    135043,
    135044
  );
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Jenkins < 1.642.2 / 1.650 and Jenkins Enterprise < 1.609.16.1 / 1.625.16.1 / 1.642.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling and management system
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins that is prior to
1.650, or a version of Jenkins LTS prior to 1.642.2; or else a version
of Jenkins Enterprise that is 1.642.x.y prior to 1.642.2.1, 1.625.x.y
prior to 1.625.16.1, or 1.609.x.y prior to 1.609.16.1. It is,
therefore, affected by the following vulnerabilities :

  - An unspecified flaw exists in the Jenkins remoting
    module. An unauthenticated, remote attacker can exploit
    this to open a JRMP listener on the server hosting the
    Jenkins master process, allowing the execution of
    arbitrary code. (CVE-2016-0788)

  - A flaw exists in main/java/hudson/cli/CLIAction.java due
    to improper sanitization of CRLF sequences, which are
    passed via CLI command names, before they are included
    in HTTP responses. An unauthenticated, remote attacker
    can exploit this, via crafted Jenkins URLs, to carry out
    an HTTP response splitting attack. (CVE-2016-0789)

  - The verification of user-supplied API tokens fails to
    use a constant-time comparison algorithm. An
    unauthenticated, remote attacker can exploit this, via
    statistical methods, to determine valid API tokens,
    thus facilitating a brute-force attack to gain access
    to user credentials. (CVE-2016-0790)

  - The verification of user-supplied XSRF crumbs fails to
    use a constant-time comparison algorithm. An
    unauthenticated, remote attacker can exploit this, via
    statistical methods, to determine valid XSRF crumbs,
    thus facilitating a brute-force attack to bypass the
    cross-site request forgery protection mechanisms.
    (CVE-2016-0791)

  - A flaw exists in groovy.runtime.MethodClosure class due
    to unsafe deserialize calls of unauthenticated Java
    objects to the Commons Collections library. An
    authenticated, remote attacker can exploit this, by
    posting a crafted XML file to certain API endpoints, to
    execute arbitrary code. (CVE-2016-0792)");
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2016-02-24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93a2c1f1");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/jenkins-security-advisory-2016-02-24");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog/");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog/-stable");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 1.650 or later, Jenkins LTS to version
1.642.2 or later, or Jenkins Enterprise to version 1.609.16.1 /
1.625.16.1 / 1.642.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/Jenkins");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

get_kb_item_or_exit("www/Jenkins/"+port+"/Installed");

url = build_url(qs:'/', port:port);

version = '';
fix = '';

if ( get_kb_item("www/Jenkins/"+port+"/enterprise/Installed") )
{
  appname = "Jenkins Enterprise by CloudBees";

  version = get_kb_item("www/Jenkins/"+port+"/enterprise/CloudBeesVersion");

  if ( version =~ "^1\.642\." )
    fix = '1.642.2.1';
  else if ( version =~ "^1\.625\." )
    fix = '1.625.16.1';
  else
    fix = '1.609.16.1';
}
else
{
  if ( get_kb_item("www/Jenkins/"+port+"/is_LTS") )
  {
    appname = "Jenkins Open Source LTS";
    fix = '1.642.2';
  }
  else
  {
    appname = "Jenkins Open Source";
    fix = '1.650';
  }

  version = get_kb_item("www/Jenkins/" + port + "/JenkinsVersion");
  if ( version == 'unknown' )
    audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);
}

# This should never ever happen
if ( empty_or_null(version) || empty_or_null(fix) )
  exit(1, "The version or fix variable was not set.");

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL           : ' + url +
    '\n  Product       : ' + appname +
    '\n  Version       : ' + version +
    '\n  Fixed version : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
