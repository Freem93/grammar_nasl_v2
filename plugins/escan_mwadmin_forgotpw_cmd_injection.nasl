#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45345);
  script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_bugtraq_id(38750);
  script_osvdb_id(62919);
  script_xref(name:"EDB-ID", value:"11720");
  script_xref(name:"Secunia", value:"38910");

  script_name(english:"eScan MWAdmin forgotpassword.php uname Parameter Arbitrary Command Execution");
  script_summary(english:"Fingerprints the vulnerability based on error message");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A PHP application hosted on the remote web server allows execution of
arbitrary commands."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MicroWorld eScan MWAdmin hosted on the remote web
server fails to properly sanitize input to the 'uname' parameter of
the 'forgotpassword.php' script before using it when calling 'exec()'.

A remote attacker could exploit this to execute arbitrary commands on
the system.  These commands can be executed as root by using the
'runasroot' program, which is included with eScan."
  );
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("escan_mwadmin_detect.nasl");
  script_require_keys("www/escan_mwadmin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 10080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");


port = get_http_port(default:10080);

install = get_install_from_kb(appname:'escan_mwadmin', port:port);
if (isnull(install))
  exit(1, "No eScan installs on port "+port+" were found in the KB.");

# make sure the 'forgot password' page exists before POSTing
url = install['dir']+'/forgotpassword.php';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>Forgot Password</title>' >!< res[2] ||
  '<input type="text" name="uname">' >!< res[2]
) exit(1, 'Error requesting '+build_url(qs:url, port:port));

to = make_list(5, 10, 20);
foreach i (to)
{
  http_set_read_timeout(i*2);
  then = unixtime();
  cmd_inj = urlencode(str:'|sleep '+i+' #'+SCRIPT_NAME+'_'+unixtime());
  res1 = http_send_recv3(
    method:"POST",
    item:url,
    port:port,
    content_type:'application/x-www-form-urlencoded',
    data:'uname='+cmd_inj+'&forgot=Send+Password',
    exit_on_fail:TRUE
  );
  now = unixtime();

  if (now - then < i || now - then > (i+5))
  {
    base_url = build_url(qs:install['dir']+'/', port:port);
    exit(0, 'The eScan MWAdmin install at '+base_url+' is not affected.');
  }
}

security_hole(port);
