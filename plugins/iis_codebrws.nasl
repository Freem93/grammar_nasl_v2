#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
# Majority of code from plugin fragment and advisory by H D Moore <hdm@digitaloffense.net>
#
# no relation :-)
#


include("compat.inc");

if(description)
{
 script_id(10956);
 script_cve_id("CVE-1999-0739");
 script_bugtraq_id(167);
 script_version("$Revision: 1.21 $");
 script_name(english:"Microsoft IIS / Site Server codebrws.asp Arbitrary Source Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"Some files may be read on the remote host.");
 script_set_attribute(attribute:"description", value:
"Microsoft's IIS 5.0 web server is shipped with a set of
sample files to demonstrate different features of the ASP
language. One of these sample files allows a remote user to
view the source of any file in the web root with the extension
.asp, .inc, .htm, or .html." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-013" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/05/07");
 script_cvs_date("$Date: 2012/03/06 20:57:09 $");
 script_osvdb_id(782);
 script_xref(name:"MSFT", value: "MS99-013");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 
 summary["english"] = "Tests for presence of Codebrws.asp";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2012 Matt Moore / HD Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

# Check simpy tests for presence of Codebrws.asp. Could be improved
# to use the output of webmirror.nasl, and actually exploit the vulnerability.

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


req = http_get(item:"/iissamples/sdk/asp/docs/codebrws.asp", port:port);
res = http_keepalive_send_recv(data:req, port:port);
if ("View Active Server Page Source" >< res)
{
    security_warning(port);
}
