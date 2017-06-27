#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12071);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2004-2274");
 script_bugtraq_id(9711);
 script_osvdb_id(4014);

 script_name(english:"Jigsaw < 2.2.4 Unspecified URI Parsing Unspecified Vulnerability");
 script_summary(english:"Checks for version of Jigsaw");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an unspecified vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"According to its banner, the remote version of Jigsaw web server has
an unspecified vulnerability related to the way it parses URIs." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.w3.org/Jigsaw/RelNotes.html#2.2.4"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Jigsaw 2.2.4 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 # details of this vuln are unknown...we'll assume worst case scenario
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/18");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if(!banner)exit(0);
 
if(egrep(pattern:"^Server: Jigsaw/([01]\.|2\.([01]\.|2\.[0-3][^0-9])).*", string:banner))
 {
   security_hole(port);
 }
