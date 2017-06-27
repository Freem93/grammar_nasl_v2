#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11377);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_name(english:"smb2www Proxy Bypass");
  script_summary(english:"smb2www Detection");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote CGI is vulnerable to an access control breach."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running smb2www - a SMB to WWW gateway.

An attacker may use this CGI to use this host as a proxy -
The attacker can then connect to a third-party SMB host without
revealing an IP address."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Enforce proper access controls to this CGI."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/14");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = make_list("/samba");

foreach d (cgi_dirs())
{
 dirs = make_list(dirs, d, string(d, "/samba"));
}

foreach d (dirs)
{
  w = http_send_recv3(method:"GET", item:string(d, "/smb2www.pl"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);

 if("Welcome to the SMB to WWW gateway" >< res){
 	security_warning(port);
	exit(0);
	}
}
