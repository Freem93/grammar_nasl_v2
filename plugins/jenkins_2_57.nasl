#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99984);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/04 19:07:45 $");

  script_cve_id(
    "CVE-2017-1000353",
    "CVE-2017-1000354",
    "CVE-2017-1000355",
    "CVE-2017-1000356"
  );
  script_bugtraq_id(
    98056,
    98062,
    98065,
    98066
  );
  script_osvdb_id(
    154967,
    156516,
    156517,
    156518,
    156519,
    156531,
    156532,
    156533,
    156534,
    156535,
    156536,
    156537,
    156538,
    156539,
    156540,
    156541,
    156542,
    156543,
    156544,
    156545,
    156546,
    156547,
    156548,
    156549,
    156550,
    156551,
    156552,
    156553,
    156554,
    156555,
    156556,
    156557,
    156558,
    156559,
    156560,
    156561
  );
  script_xref(name:"IAVA", value:"2017-A-0132");

  script_name(english:"Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to
2.57 or is a version of Jenkins LTS prior to 2.46.2, or else it is
a version of Jenkins Enterprise that is 1.625.x.y prior to 1.625.24.1,
1.651.x.y prior to 1.651.24.1, 2.7.x.0.y prior to 2.7.24.0.1, or
2.x.y.z prior to 2.46.2.1. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists within
    core/src/main/java/jenkins/model/Jenkins.java that
    allows an untrusted serialized Java SignedObject to be
    transfered to the remoting-based Jenkins CLI and
    deserialized using a new ObjectInputStream. By using a
    specially crafted request, an unauthenticated, remote
    attacker can exploit this issue to bypass existing
    blacklist protection mechanisms and execute arbitrary
    code. (CVE-2017-1000353)

  - A flaw exists in the remoting-based CLI, specifically in
    the ClientAuthenticationCache.java class, when storing
    the encrypted username of a successfully authenticated
    user in a cache file that is used to authenticate
    further commands. An authenticated, remote attacker who
    has sufficient permissions to create secrets in Jenkins
    and download their encrypted values can exploit this
    issue to impersonate any other Jenkins user on the same
    instance. (CVE-2017-1000354)

  - A denial of service vulnerability exists in the XStream
    library. An authenticated, remote attacker who has
    sufficient permissions, such as creating or configuring
    items, views or jobs, can exploit this to crash the Java
    process by using specially crafted XML content.
    (CVE-2017-1000355)

  - Cross-site request forgery (XSRF) vulnerabilities exist
    within multiple Java classes due to a failure to require
    multiple steps, explicit confirmation, or a unique token
    when performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit these to
    perform several administrative actions by convincing a
    user into opening a specially crafted web page.
    (CVE-2017-1000356)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2017-04-26");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2017-04-26/");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.57 or later, Jenkins LTS to version
2.46.2 or later, or Jenkins Enterprise to version 1.625.24.1 /
1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
if (get_kb_item("www/Jenkins/"+port+"/enterprise/Installed"))
{
  appname = "Jenkins Enterprise by CloudBees";
  version = get_kb_item("www/Jenkins/"+port+"/enterprise/CloudBeesVersion");

  if (version =~ "^1\.651\.")
  {
    fix = '1.651.24.1';
  }
  else if (version =~ "^1\.625\." )
  {
    fix = '1.625.24.1';
  }
  else if (version =~ "^2\.7\." )
  {
    fix = '2.7.24.0.1';
  }
  else
  {
    fix = '2.46.2.1';
  }
}
else
{
  if (get_kb_item("www/Jenkins/"+port+"/is_LTS") )
  {
    appname = "Jenkins Open Source LTS";
    fix = '2.46.2';
  }
  else
  {
    appname = "Jenkins Open Source";
    fix = '2.57';
  }

  version = get_kb_item("www/Jenkins/" + port + "/JenkinsVersion");
  if (version == 'unknown')
  {
    audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);
  }
}

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL           : ' + url +
    '\n  Product       : ' + appname +
    '\n  Version       : ' + version +
    '\n  Fixed version : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xsrf:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
