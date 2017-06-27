#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10368);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2014/05/25 23:45:39 $");

 script_cve_id("CVE-2000-0252", "CVE-2000-0253", "CVE-2000-0254");
 script_bugtraq_id(1115);
 script_osvdb_id(281, 38367, 38368);

 script_name(english:"Dansie Shopping Cart Backdoor Detection");
 script_summary(english:"Determines the presence of Dansie Shopping Cart");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The script /cart/cart.cgi is present.

If this shopping cart system is the Dansie Shopping Cart, and if it is
older than version 3.0.8 then it is very likely that it contains a
backdoor that allows anyone to execute arbitrary commands on this
system.");
 script_set_attribute(attribute:"solution", value:"Use another cart system.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/04/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

res  = is_cgi_installed3(item:"/cart/cart.cgi", port:port);
if( res )security_hole(port);


