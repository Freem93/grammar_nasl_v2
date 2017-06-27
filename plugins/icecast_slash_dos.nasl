#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15400);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2001-1083");
 script_bugtraq_id(2933);
 script_osvdb_id(5472);
 script_xref(name:"DSA", value:"089");
 script_xref(name:"RHSA", value:"2002:063");
 
 script_name(english:"Icecast Crafted URI Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming media server is affected by a remote denial of
service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of Icecast, an open source 
streaming audio server that is older than version 1.3.11.

This version is affected by a remote denial of service because
Icecast server does not properly sanitize user-supplied input.

A remote attacker could send a specially crafted URL, by adding '/', 
'\' or '.' to the end, that may result in a loss of availability for 
the service.

*** Nessus reports this vulnerability using only
*** information that was gathered." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 1.3.12 or later, as this reportedly fixes the
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/09");
 script_cvs_date("$Date: 2014/05/01 21:32:45 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:icecast:icecast");
script_end_attributes();

 
 summary["english"] = "Check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");		
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
if ( ! banner ) exit(0);

if("icecast/1." >< banner &&  egrep(pattern:"icecast/1\.(1\.|3\.([0-9]|10)[^0-9])", string:banner))
      security_warning(port);
