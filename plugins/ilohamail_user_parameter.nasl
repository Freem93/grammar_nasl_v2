#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description)
{
  script_id(14637);
  script_version("$Revision: 1.12 $");

# NOTE: no CVE id assigned (gat, 09/2004)
  script_bugtraq_id(9131);
  script_osvdb_id(2879);
 
  script_name(english:"IlohaMail user Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an PHP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is running IlohaMail
version 0.8.10 or earlier.  Such versions do not properly sanitize the
'user' parameter before using it to generate dynamic HTML output.  An
attacker may be able to leverage this to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce7ea0ed" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.8.12 or later. 

Note that 0.8.11 was released to address this issue, but that version
has a crippling bug." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/01");
 script_cvs_date("$Date: 2015/01/23 22:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for User Parameter vulnerability in IlohaMail");
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_family(english:"CGI abuses : XSS");

  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ilohamail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if (ver =~ "^0\.([0-7].*|8\.([0-9]|10)(-Devel)?$)")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
