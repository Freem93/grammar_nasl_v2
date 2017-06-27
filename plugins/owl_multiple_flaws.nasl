#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16063);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2005-0264", "CVE-2005-0265");
 script_bugtraq_id(12114);
 script_osvdb_id(12677, 12678);

 script_name(english:"Owl < 0.74.0 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using owl intranet engine, an open source
file sharing utility written in php.

The remote version of this software is vulnerable to various
flaws, which may allow an attacker to execute arbitrary SQL
statements against the remote database or to perform a cross
site scripting attack against third-party users by using the
remote server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Owl 0.74.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/01");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:owl:owl_intranet_engine");
script_end_attributes();

 script_summary(english:"Determines owl is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);


foreach d ( cgi_dirs() )
{
 w = http_send_recv3(method:"GET", item:d + "/browse.php", port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 line = egrep(pattern:"<TITLE>Owl Intranet Owl ", string:res);
 if ( line )
 {
  if ( ereg(pattern:".*Owl 0\.([0-6].*|7[0-3])</TITLE>", string:line) )
	{
	 security_hole(port);
	 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 exit(0);
	}
 }
}
