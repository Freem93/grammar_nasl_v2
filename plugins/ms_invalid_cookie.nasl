#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12229);
 script_version ("$Revision: 1.15 $");
 script_osvdb_id(5993);

 
 script_name(english:"Microsoft IIS Cookie information disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft IIS with what appears to be a
a vulnerable disclosure of cookie usage.  That is, when sent a 
Cookie with the '=' character, Microsoft IIS will either respond
with an error (if actually processing the cookie via a specific
asp page) or disclose information of the .inc file used.  This can
be used to map applications which are processing cookies." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/May/261" );
 script_set_attribute(attribute:"solution", value:
"Configure IIS to return custom error pages." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/06");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Microsoft IIS Cookie information disclosure");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# make sure it's IIS
banner = get_http_banner(port: port);
if (! egrep(string:banner, pattern:"Server: Microsoft-IIS") ) exit(0);

scripts = get_kb_list(string("www/", port, "/cgis"));
if(isnull(scripts)) exit(0);

scripts = make_list(scripts);

disable_cookiejar();
foreach script (scripts) {
    script = ereg_replace(string:script,
                         pattern:"(.*) - .*",
                         replace:"\1");

    r = http_send_recv3(port: port, method: "GET", item: script, version: 10, 
add_headers: make_array("Cookie", "=") );
    if (isnull(r)) exit(0);
    res = r[1]+r[2];
    if(egrep(pattern:"Unspecified error", string:res)) {
        if (egrep(pattern:"\.inc, line|\.asp, line", string:res)) {
                security_warning(port);
                exit(0);
        }
    }
}

