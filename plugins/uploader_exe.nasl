#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10291);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2014/05/27 00:15:38 $");

 script_cve_id("CVE-1999-0177");
 script_osvdb_id(229);

 script_name(english:"O'Reilly WebSite uploader.exe Arbitrary File Upload");
 script_summary(english:"Checks for the presence of /cgi-win/uploader.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution.");
 script_set_attribute(attribute:"description", value:
"The remote web server contains a CGI script named 'uploader.exe' in
'/cgi-win'. Versions of O'Reilly's Website product before 1.1g
included a script with this name that allows an attacker to upload
arbitrary CGI and then execute them.");
 script_set_attribute(attribute:"see_also", value:"http://insecure.org/sploits/oreily.website.uploader.exe.html");
 script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/294");
 script_set_attribute(attribute:"solution", value:
"Verify that the affected script does not allow arbitrary uploads and
remove it if it does.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/09/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

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
cgi = "/cgi-win/uploader.exe";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);

