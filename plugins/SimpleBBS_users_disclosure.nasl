#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11345);
 script_version ("$Revision: 1.21 $");

 script_bugtraq_id(7045);
 script_osvdb_id(53303);

 script_name(english:"SimpleBBS users disclosure");
 script_summary(english:"Checks for the presence of users.php");

 script_set_attribute(attribute:"synopsis",
  value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote installation of SimpleChat allows an unauthenticated, remote
attacker to retrieve its user database via a direct request to
'data/usr', which contains confidential information such as user
passwords." );
 script_set_attribute(
  attribute:"solution", 
  value:"Unknown at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/10");
 script_cvs_date("$Date: 2011/08/30 19:41:04 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port)) exit(0);

dirs = make_list(cgi_dirs());
foreach dir (dirs)
{
 url = string(dir, "/users/users.php");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);

 if (
  res[0] =~ "^HTTP/1\/[01] 200 " &&
  "username" >< res[2] && 
  egrep(pattern:".*username.*password.*email", string:res[2])
 )
 {
   if (report_verbosity > 0)
   {
    report = string(
     "\n",
     "The following request can be used to verify the issue :\n",
     "\n",
     "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
   }
   else security_warning(port);

   exit(0);
 }
}
