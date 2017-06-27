#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15401);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2002-0177");
 script_bugtraq_id(4415);
 script_osvdb_id(10445);
 
 script_name(english:"Icecast MP3 Client HTTP GET Request Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming audio server is affected by a remote buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of Icecast, an open source 
streaming audio server, which is older than version 1.3.12.

This version is affected by a remote buffer overflow because it does
not properly check bounds of data sent from clients. 

As a result of this vulnerability, it is possible for a remote attacker to
cause a stack overflow and then execute arbitrary code with the 
privileges of the server.

*** Nessus reports this vulnerability using only
*** information that was gathered." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/29" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/46" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/74" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/04/02");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/1." >< banner && 
   egrep(pattern:"icecast/1\.([012]\.|3\.([0-9]|1[01])[^0-9])", string:banner))
      security_hole(port);
