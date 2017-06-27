#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12089);
 script_bugtraq_id(9790);
 script_version ("$Revision: 1.11 $");
 
 script_name(english:"HotOpentickets Privilege Escalation");
 script_summary(english:"Checks for HotOpenTicket");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HotOpenTickets, a web-based ticketing
system. A vulnerability has been disclosed in all versions of this
software before version 02272004_ver2c which may allow an attacker to
escalate privileges on this server." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=355697" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Hot Open Tickets 02272004_ver2c or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/04");
 script_cvs_date("$Date: 2011/03/14 21:48:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc."); 
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach d ( cgi_dirs() )
{
  res = http_send_recv3(method:"GET", item:string(d, "/login.php"), port:port, exit_on_fail: 1);

  if (egrep(pattern:"^hot_[0-9]*2003_ver(1|2[ab])", string:res[2]))
  {
    security_warning(port:port);
  }
}
