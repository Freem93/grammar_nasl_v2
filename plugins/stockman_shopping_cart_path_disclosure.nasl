#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11568);
  script_version ("$Revision: 1.15 $");
  script_osvdb_id(53332);
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"StockMan Shopping Cart shop.plx Path Disclosure");
  script_summary(english:"determines the remote root path");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running the StockMan shopping cart.

There is a flaw in this version that could allow an attacker to obtain
the physical path to the remote web root by requesting a non-exisant
page through the \'shop.plx\' CGI.

An attacker may use this flaw to gain more knowledge about the setup
of the remote host.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to StockMan Shopping Cart Version 7.9 or newer.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/05");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function check(loc)
{
 local_var	w, r;
 w = http_send_recv3(item:string(loc, "/shop.plx/page=nessus"+rand()), 
   method:"GET", port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 r = strcat(w[0], w[1], '\r\n', w[2]);

 if(egrep(pattern:".*Error opening HTML file: /.*/nessus", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
