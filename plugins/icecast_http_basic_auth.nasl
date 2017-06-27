#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15397);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2004-2027");
 script_bugtraq_id(10311);
 script_osvdb_id(6075);
 script_xref(name:"GLSA", value:"200405-10");
 
 script_name(english:"Icecast HTTP Basic Authorization Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote media server is vulnerable to a remote denial of service
attack." );
 script_set_attribute(attribute:"description", value:
"The remote server runs Icecast 2.0.0, an open source streaming audio 
server.

This version is affected by a remote denial of service.

A remote attacker could send a specially crafted URL, with a long 
string passed in an Authorization header that will result in a loss
of availability for the service.

*** Nessus reports this vulnerability using only
*** information that was gathered." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5065a57" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/May/387" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 2.0.1 or later, as this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/09");
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
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if (! banner ) exit(0);
if("icecast/" >< banner && egrep(pattern:"icecast/2\.0\.0([^0-9]|$)", string:banner))
      security_warning(port);
