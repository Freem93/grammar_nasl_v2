#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15399);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2001-1230");
 script_bugtraq_id(4743);
 script_osvdb_id(10444);
 
 script_name(english:"Icecast Multiple Unspecified Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming media server is affected by a remote buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of Icecast, an open source 
streaming audio server, which is older than version 1.3.10.

This version is affected by a remote buffer overflow.

As a result of this vulnerability, it is possible for a remote 
attacker to execute arbitrary code with the privilege of the server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Mar/198" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 1.3.10 or later, as this reportedly fixes the 
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/03/13");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port)exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/" >< banner && egrep(pattern:"icecast/1\.(1\.|3\.[0-9][^0-9])", string:banner)) security_hole(port);
