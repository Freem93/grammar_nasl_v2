#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10078);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_bugtraq_id(1205);
 script_osvdb_id(68);

 script_name(english:"Microsoft FrontPage Extensions authors.pwd Information Disclosure");
 script_summary(english:"Checks for the presence of Microsoft FrontPage extensions");

 script_set_attribute(attribute:"synopsis", value:"The remote web server has an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running with Microsoft FrontPage
extensions. The file 'authors.pwd', which contains the encrypted
passwords of FrontPage authors, can by accessed by anyone. A remote
attacker could decrypt these passwords, or possibly overwrite this
file.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1998/Apr/169");
 script_set_attribute(attribute:"solution", value:
"Change the permissions of the '/vti_vt' directory to prevent access by
unauthenticated web users.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
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

sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);
res = is_cgi_installed3(item:"/_vti_pvt/authors.pwd", port:port);
if ( res ) security_warning(port);
