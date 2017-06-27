#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71215);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"Jenkins Accessible without Credentials");
  script_summary(english:"Tries to access Jenkins management");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a job scheduling / management system that
is accessible without authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts Jenkins, a job scheduling / management
system and a drop-in replacement for Hudson.  By allowing
unauthenticated access to the application, anyone may be able to
configure Jenkins and jobs, and perform builds. 

Additionally, this script checks for unauthenticated access to
'/scripts' as anyone with access to the script console can run arbitrary
Groovy scripts on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://wiki.jenkins-ci.org/display/JENKINS/Securing+Jenkins");
  script_set_attribute(attribute:"solution", value:
"Refer to the Jenkins security guide for information on restricting
access to Jenkins.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("jenkins_detect.nasl");
  script_require_keys("www/Jenkins");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

get_kb_item_or_exit("www/Jenkins/"+port+"/Installed");
urls = make_list();

# Check for access to management options
url = "/manage";
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : url,
  exit_on_fail : TRUE
);

if (egrep(pattern:"\<title\>Manage (Jenkins \[Jenkins\]|Hudson \[Hudson\])\</title\>", string:res[2], icase:TRUE)) urls = make_list(urls, url);

# Check to see if Hudson is locked down.  Access to /manage will still exist
# but we should get a 403 response if we try an access any config options
else if (egrep(pattern:"\<title\>(System Management \[Hudson\]|Configuration \[Hudson\])\</title\>", string:res[2], icase:TRUE))
{
  url = "/configure";
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url,
    exit_on_fail : TRUE
  );

  if (
    ">Home directory<" >< res[2] && 
    '"setting-name">Hudson URL<' >< res[2]
  ) urls = make_list(urls, url);
}

# Check for access to Groovy script console
url = "/script";
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : url,
  exit_on_fail : TRUE
);

if (
  ">Script Console<" >< res[2] &&
  egrep(pattern:"Type in (an |\s)?arbitrary", string:res[2]) &&
  ">Groovy script<" >< res[2]
) urls = make_list(urls, url);

if (max_index(urls) > 0)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:urls, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Jenkins", port);
