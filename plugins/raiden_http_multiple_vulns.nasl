#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17243);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(12688);
 script_osvdb_id(14303, 14304);

 script_name(english: "RaidenHTTPD < 1.1.34 Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RaidenHTTPD 1.1.33 or older. 

Ther are various flaws in the remote version of this server which may
allow an attacker to disclose the source code of any PHP file hosted
on the remote server, or to execute arbitrary code on the remote with
the privileges of the remote server (usually SYSTEM)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RaidenHTTPD 1.1.34 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/02");
 script_cvs_date("$Date: 2011/03/17 16:19:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "RaidenHTTPD check");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
banner = get_http_banner(port: port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"Server: RaidenHTTPD/(0\.|1\.0|1\.1\.[0-9] |1\.1\.[0-2][0-9] |1\.1\.3[0-3] )", string:banner) ) security_hole ( port );
