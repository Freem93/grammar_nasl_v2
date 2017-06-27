#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#

include("compat.inc");

if(description)
{
 script_id(11109);
 script_cve_id("CVE-2002-1435");
 script_bugtraq_id(5552);
 script_osvdb_id(14538);
 script_version ("$Revision: 1.28 $");

 script_name(english:"Achievo class.atkdateattribute.js.php config_atkroot Parameter Remote File Inclusion");
 script_summary(english:"Checks for the presence of Achievo");
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a resource management tool which is
affected by a remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Achievo, a web-based resource management
tool written in PHP.

The version of Achievo on the remote host includes a PHP script which
is reported to be affected by a remote file include vulnerability. 
An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server. Note that
this flaw is only present if PHP register_globals is set to 'on'. The
attacker must also be able to store the attack code on a server that
is accessible by the web server." );

 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Aug/330");
 script_set_attribute(attribute:"solution", value:
"Upgrading to Achievo 1.2 or newer reportedly fixes this problem." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/22");
 script_cvs_date("$Date: 2016/09/23 20:00:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
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

if(!can_host_php(port:port)) exit(0);



tmp = cgi_dirs();
dir = NULL;
foreach d (tmp)
{
 if(isnull(dir))dir = make_list(d, string(d, "/achievo"));
 else dir = make_list(dir, d, string(d, "/achievo"));
}


for(i = 0; dir[i] ; i = i +  1)
 {
  w = http_send_recv3(method:"GET", item:string(dir[i], "//atk/javascript/class.atkdateattribute.js.php?config_atkroot=http://xxxxxxxxxx/"),
 		port:port);
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("http://xxxxxxxxxx/atk/" >< r)
  {
 	security_warning(port);
	exit(0);
  }
}
