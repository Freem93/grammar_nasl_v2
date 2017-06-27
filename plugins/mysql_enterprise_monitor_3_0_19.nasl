#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83296);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2014-7809");
  script_bugtraq_id(71548);
  script_osvdb_id(115217);

  script_name(english:"MySQL Enterprise Monitor 3.0.x < 3.0.19 Apache Struts Predictable Token XSRF");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a
cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
running on the remote host may be affected by a cross-site request
forgery vulnerability due to the token generator failing to adequately
randomize the token values. A remote attacker can exploit this by
extracting a token from a form and then predicting the next token
value that will be used to secure form submissions. By convincing a
victim to visit a specially crafted form, the attacker can then use
the predicted token value to force an action for a logged in user.

Note that this vulnerability can only be exploited when the <s:token/>
tag is used within a form.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-023.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/WW-4423");

  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Enterprise Monitor 3.0.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:enterprise_monitor");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "MySQL Enterprise Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

fix  = "3.0.19";
port = get_http_port(default:18443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
install_url = build_url(port:port, qs:"/");

if (version =~ "^3\.0($|[^0-9])" && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
