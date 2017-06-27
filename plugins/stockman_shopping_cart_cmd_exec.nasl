#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11569);
  script_version ("$Revision: 1.16 $");
  script_bugtraq_id(7485);
  script_osvdb_id(53331);

  script_name(english:"StockMan Shopping Cart shop.plx page Parameter Arbitrary Command Execution");
  script_summary(english:"Determines the version of shop.plx");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to authentication bypass.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running the StockMan shopping cart.

According to the version number of the CGI shop.plx, there is
a flaw in this installation that could allow an attacker to
execute arbitrary commands on this host, and which could also
allow him to obtain your list of customers or their credit
card number.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to StockMan Shopping Cart Version 7.9 or newer'
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/05");
 script_cvs_date("$Date: 2011/12/14 21:50:18 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
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
 local_var	r, w;
 w = http_send_recv3(method:"GET", item:string(loc, "/shop.plx"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:"Stockman Shopping Cart Version ([0-6]\.|7\.[0-8])", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
