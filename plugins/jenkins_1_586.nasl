#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83956);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2014-9634", "CVE-2014-9635");
  script_bugtraq_id(72054);
  script_osvdb_id(117538, 117539);

  script_name(english:"Jenkins < 1.565.3 / 1.586 Multiple Vulnerabilities");
  script_summary(english:"Checks for the HttpOnly Cookie flag.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling and management system
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins (open source) that
is affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to
    not setting the 'Secure' flag for session cookies. This
    results in the web browser transmitting the cookie in
    cleartext, allowing a man-in-the-middle attacker to
    disclose sensitive information. (CVE-2014-9634)

  - A security bypass vulnerability exists due to the
    'HttpOnly' attribute for session cookies not being used
    in 'main/java/hudson/WebAppMain.java'. This allows a
    remote attacker to conduct a cross-site scripting 
    attack. (CVE-2014-9635)");
  script_set_attribute(attribute:"see_also", value:"https://issues.jenkins-ci.org/browse/JENKINS-25019");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog/");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog/-stable");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.565.3 / 1.586 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

# Check if install is Enterprise
enterprise_installed = get_kb_item("www/Jenkins/"+port+"/enterprise/Installed");
if (!isnull(enterprise_installed)) exit(0, "Jenkins Enterprise by CloudBees is not affected.");

appname = "Jenkins Open Source";

url = build_url(qs:'/', port:port);

# Test the Cookie for HttpOnly
init_cookiejar();

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

cook = get_http_cookie_keys(name_re:'.*');
if (isnull(cook)) exit(1, "The CookieJar is disabled.");

val = get_http_cookie_from_key(cook[0]);

if (val['httponly'] != 1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Product           : ' + appname +
      '\n  Fixed version     : 1.586 / 1.565.3' +
      '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);
