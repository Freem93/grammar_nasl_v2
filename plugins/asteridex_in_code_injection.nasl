#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25674);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3621");
  script_bugtraq_id(24781);
  script_osvdb_id(37846);
  script_xref(name:"EDB-ID", value:"4151");

  script_name(english:"AsteriDex callboth.php Multiple Parameter CRLF Injection Arbitrary Command Execution");
  script_summary(english:"Checks if AsteriDex's callboth.php script filters newlines");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that may allow execution
of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AsteriDex, a web-based dialer and address
book for Asterisk. 

The version of AsteriDex installed on the remote host fails to
sanitize input to the 'IN' parameter of the 'callboth.php' script
before passing it to the Asterisk Call Manager as part of the data
stream of an authenticated session.  Using a valid SIP address that
answers when dialed, an unauthenticated attacker can leverage this
issue to execute arbitrary code on the remote host subject to the
privileges of the user id under which Asterisk runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/472907/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to AsteriDex version 3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/06");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/asteridex", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  exploit = string(unixtime(), "@nessus\r\n", SCRIPT_NAME);
  r = http_send_recv3(method:"GET", port:port,
    item:string(
      dir, "/callboth.php?",
      "SEQ=654321&",
      "OUT=123456&",
      "IN=", urlencode(str:exploit) ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if the CR/LF was not filtered out.
  if (string("Extension SIP/", exploit, " is ringing now") >< res)
  {
    security_hole(port);
    exit(0);
  }
}
