#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Marc Bromm" <theblacksheep@fastmail.fm>
#  To: bugtraq@securityfocus.com
#  Date: Mon, 09 Jun 2003 09:25:19 -0800
#  Subject: Several bugs found in "Spyke's PHP Board"

include( 'compat.inc' );

if(description)
{
 script_id(11706);
 script_version ("$Revision: 1.20 $");
 script_bugtraq_id(7856);
 script_osvdb_id(4388, 4389);

 script_name(english:"Spyke Multiple Remote Vulnerabilities");
 script_summary(english:"Checks for the presence of info.dat");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to an information
disclosure vulnerability.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is using Spyke - a web board written in PHP.

This board stores vital information in the file info.dat,
which can be downloaded by anyone. This file contains
the name of the administrator of the website, as well as
its password.

Another flaw lets an attacker download information about
any user simply by knowing their name.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'There are no known fixes.  Discontinue use of Spyke.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.nessus.org/u?ab26819a'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/09");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl","http_version.nasl");
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
 local_var r, w;

 w = http_send_recv3(method:"GET", item:string(loc, "/info.dat"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("$adminpw" >< r )
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}
