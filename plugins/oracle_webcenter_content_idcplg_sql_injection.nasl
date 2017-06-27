#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57980);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/04 16:15:43 $");

  script_cve_id("CVE-2012-0083");
  script_bugtraq_id(51451);
  script_osvdb_id(78403);

  script_name(english:"Oracle WebCenter Content 'GET_SEARCH_RESULTS' SQL Injection");
  script_summary(english:"Checks 'SortOrder' parameter for SQL injection vulnerability");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a SQL injection vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The Oracle WebCenter Content install on the remote host does not
properly sanitize the 'SortField', 'SortOrder', and 'QueryText'
parameters of the 'GET_SEARCH_RESULTS' IDC service.  An attacker can
exploit this flaw to launch SQL injection attacks which could lead to
authentication bypass, disclosure of sensitive information, and
attacks against the underlying database."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f19d081");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");
  script_set_attribute(
    attribute:"solution",
    value:
"See the Oracle advisory for information on obtaining and applying bug
fix patches."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_webcenter_content_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Oracle WebCenter Content");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app_name = "Oracle WebCenter Content";

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app_name, port:port);

dir = install['path'];

install_url = build_url(port: port, qs:dir);

# This should cause the app to return an error (default configuration)
# since the from clause is missing.
sql_injection = "%28select+1%29";

url = dir +
  "/idcplg?IdcService=" +
  "GET_SEARCH_RESULTS&SortField=" + sql_injection +
  "&SortOrder=Desc&ResultCount=20&QueryText=%3Cqsch%3EF%3C/qsch%3E";

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if (
  "FROM keyword not found where expected" >< res[2] &&
  "ORDER BY (select 1)" >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'The following request can be used to verify the vulnerability :' +
      '\n' +
      build_url(port:port, qs:url) +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
