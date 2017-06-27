#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10142);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2014/05/26 01:15:51 $");

 script_cve_id("CVE-1999-0386");
 script_osvdb_id(111);

 script_name(english:"Microsoft Personal Web Server Multiple Dot Request Arbitrary File Access");
 script_summary(english:"......../file.txt");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to read any file on the remote system by prepending
several dots before the file name.");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;[LN];217763");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=91668256428214&w=2");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"1996/01/17");
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
cgi = "/................../config.sys";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_warning(port);


