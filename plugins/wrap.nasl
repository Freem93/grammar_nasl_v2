#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10317);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2014/05/27 00:36:24 $");

 script_cve_id("CVE-1999-0149");
 script_bugtraq_id(373);
 script_osvdb_id(247);

 script_name(english:"IRIX wrap CGI Traversal Arbitrary Directory Listing");
 script_summary(english:"Checks for the presence of /cgi-bin/wrap");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to
information disclosure.");
 script_set_attribute(attribute:"description", value:
"The 'wrap' CGI is installed. This CGI allows anyone to get a listing
for any directory with mode +755.

Note that not all implementations of 'wrap' are vulnerable.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/lists/bugtraq/1997/Apr/0076.html");
 script_set_attribute(attribute:"solution", value:"Remove this CGI script.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/04/02");
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
res = is_cgi_installed3(port:port, item:"wrap");
if(res)security_warning(port);

