#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10649);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_osvdb_id(538);

 script_name(english:"processit CGI Environment Variable Remote Information Disclosure");
 script_summary(english:"Checks for the presence of /cgi-bin/processit");

 script_set_attribute(attribute:"synopsis", value:"The remote web is affected by an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'processit' CGI is installed. processit normally returns all
environment variables.

This gives an attacker valuable information about the configuration of
your web server.");
 script_set_attribute(attribute:"solution", value:"Remove it from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/04/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl");
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

cgi = "processit.pl";
res = is_cgi_installed3(port:port, item:cgi);
if(res)security_warning(port);

