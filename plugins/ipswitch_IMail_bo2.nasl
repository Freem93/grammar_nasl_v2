#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(15771);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-1520");
 script_bugtraq_id(11675);
 script_xref(name:"OSVDB", value:"11838");
 
 script_name(english:"Ipswitch IMail IMAP Service DELETE Command Remote Overflow");
 script_summary(english:"Checks for version of IMail web interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Ipswitch IMail that
is older than version 8.14.0.

The remote version of this software is vulnerable to a buffer overflow
when it processes the argument of the 'delete' command. An attacker
may exploit this flaw to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Nov/188" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IMail 8.14 or later, as this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mdaemon 8.0.3 IMAPD CRAM-MD5 Authentication Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/12");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:imail");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port, exit_on_fail: 1);
serv = egrep(string: banner, pattern: "^Server:.*");
if(ereg(pattern:"^Server:.*Ipswitch-IMail/([1-7]\..*|(8\.(0[0-9]?[^0-9]|1[0-3][^0-9])))", string:serv))
   security_warning(port);
