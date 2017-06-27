#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21729);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-7049");
  script_bugtraq_id(18484);
  script_osvdb_id(26543);

  script_name(english:"Wikka wikka.php Local File Inclusion");
  script_summary(english:"Tries to read a local file in Wikka");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Wikka, a lightweight, open source wiki
application written in PHP. 

The version of Wikka installed on the remote host has a programming
error in the 'Method()-method' in 'wikka.php'.  By leveraging this
issue, an unauthenticated attacker may be able to access arbitrary PHP
files on the affected host and execute them, subject to the privileges
of the web server user id. 

Note that successful exploitation is unaffected by the setting of PHP
'register_globals' but only works with files with the extension
'.php'." );
 script_set_attribute(attribute:"see_also", value:"http://wush.net/trac/wikka/ticket/36" );
 script_set_attribute(attribute:"see_also", value:"http://wikkawiki.org/WikkaReleaseNotes#hn_Wikka_1.1.6.2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wikka version 1.1.6.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/16");
 script_cvs_date("$Date: 2013/01/07 22:52:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:wikkawiki:wikkawiki");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/wikka", "/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/wikka.php?",
      "wakka=HomePage/../../actions/wikkachanges"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if we see the release notes.
  if ("<h2>Wikka Release Notes</h2>" >< res) {
    security_hole(port);
    exit(0);
  }
}
