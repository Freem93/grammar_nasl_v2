#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10600);
 script_version ("$Revision: 1.23 $");

 script_cve_id("CVE-2001-0197");
 script_bugtraq_id(2264);
 script_osvdb_id(496);
 
 script_name(english:"Icecast utils.c fd_write Function Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to a remote code execution attack." );
 script_set_attribute(attribute:"description", value:
"The remote server claims to be running Icecast 1.3.7 or 1.3.8beta2.

These versions are vulnerable to a format string attack that could
allow an attacker to execute arbitrary commands on this host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/0323.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/01/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/22");
 script_cvs_date("$Date: 2011/12/16 22:59:43 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Icecast format string");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8000);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/" >< banner && egrep(pattern:"icecast/1\.3\.(7|8 *beta[012])", string:banner))
      security_hole(port);
