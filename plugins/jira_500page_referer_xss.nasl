#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45578);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id("CVE-2010-1164");
  script_bugtraq_id(39485);
  script_osvdb_id(64333);
  script_xref(name:"Secunia", value:"39353");

  script_name(english:"Atlassian JIRA 500page.jsp Referer XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
cross-site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Atlassian JIRA installation hosted on the remote web server is
affected by a cross-site scripting (XSS) vulnerability in the
500page.jsp file due to an HTTP 'referer' field not being properly
sanitized before being displayed in the page. A remote attacker can
exploit this, by tricking a user into making a specially crafted
request, to execute arbitrary script code.

This version of JIRA is also affected by additional vulnerabilities
(cross-site scripting and privilege escalation); however, Nessus has
not tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.apache.org/infra/entry/apache_org_04_09_2010");
  # https://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2010-04-16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2faf685");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the JIRA security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

xss = '<script>alert("'+SCRIPT_NAME+'-'+unixtime()+'")</script>';
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + '/500page.jsp',
  add_headers  : make_array("Referer", xss),
  exit_on_fail : TRUE
);

pattern = 'Referer URL:[ \\r\\n\\t]*<b>'+xss+'</b>';
pattern = str_replace(string:pattern, find:'(', replace:'\\(');
pattern = str_replace(string:pattern, find:')', replace:'\\)');

if (ereg(string:res[2], pattern:pattern, multiline:TRUE))
{
  output = eregmatch(string:res[2], pattern:pattern);
  if (!empty_or_null(output[0])) output = output[0];
  else output = res[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 3,
    xss        : TRUE,
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app,  build_url(qs:dir, port:port));
