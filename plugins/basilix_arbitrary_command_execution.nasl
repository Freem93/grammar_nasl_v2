#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#



include("compat.inc");

if (description) {
  script_id(14304);
  script_version ("$Revision: 1.16 $");
 
  script_bugtraq_id(3276);
  script_osvdb_id(49381);

  name["english"] = "BasiliX login.php3 username Variable Arbitrary Command Execution";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of BasiliX between
1.0.2beta or 1.0.3beta.  In such versions, the script 'login.php3'
fails to sanitize user input, which enables a remote attacker to pass
in a specially crafted value for the parameter 'username' with
arbitrary commands to be executed on the target using the permissions
of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2001-09/0017.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BasiliX version 1.1.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_cvs_date("$Date: 2011/03/17 01:57:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for arbitrary command execution vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2011 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/basilix");
  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.0\.[23]") {
    security_warning(port);
    exit(0);
  }
}
