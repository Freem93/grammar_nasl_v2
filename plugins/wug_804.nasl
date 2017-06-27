#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19680);
  script_version("$Revision: 1.14 $");

  script_bugtraq_id(14797, 14799);
  script_osvdb_id(19303, 19304);

  script_name(english:"Ipswitch WhatsUp Gold <= 8.04 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server can be used to reveal script source code and
contains an ASP script that is prone to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WhatsUp Gold, an applications and network
monitor and management system for Windows from Ipswitch. 

The installed version of WhatsUp Gold returns a script's source code
in response to a URI with an uppercase file extension.  This may lead
to the disclosure of sensitive information or subsequent attacks
against the affected application.  In addition, WhatsUp Gold also is
prone to cross-site scripting attacks because it fails to sanitize
user-supplied input to the 'map' parameter of the 'map.asp' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.cirt.dk/advisories/cirt-34-advisory.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.cirt.dk/advisories/cirt-35-advisory.pdf" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/09");
 script_cvs_date("$Date: 2015/02/13 21:07:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
script_end_attributes();

 
  script_summary(english:"Checks for multiple vulnerabilities in WhatsUp Gold <= 8.04");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Don't bother checking if it doesn't look like WhatsUp Gold.
banner = get_http_banner(port:port);
if (!banner || "WhatsUp_Gold" >!< banner) exit(0);


# Try to exploit the first flaw to display a script's source code.
if (thorough_tests) scripts = make_list("default.ASP", "topview.ASP", "UserCreate.ASP");
else scripts = make_list("UserCreate.ASP");

foreach script (scripts) {
  # nb: access to the script requires authorization; try the
  #     user 'guest', which by default has an empty password.
  w = http_send_recv3(method:"GET", item:string("/", script), port:port, 
    username: "guest", password: "");
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if we see the source code.
  if (egrep(string:res, pattern:"<%(else|endif|if|include)%", icase:TRUE)) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
