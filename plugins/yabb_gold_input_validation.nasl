#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(14806);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2004-2139", "CVE-2004-2140");
 script_bugtraq_id(11235);
 script_osvdb_id(10221, 10222);

 script_name(english:"YaBB 1 Gold < 1.3.2 Multiple Input Validation Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
multiple cross-site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the YaBB 1 Gold web forum software. 

According to its version number, the remote version of this software
is vulnerable to various input validation issues which may allow an
attacker to perform cross-site scripting or HTTP splitting attacks
against the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?636e6430" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to YaBB 1 Gold SP 1.3.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/22");
 script_cvs_date("$Date: 2015/02/13 21:07:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines the version of YaBB 1 Gold");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);


if (thorough_tests) dirs = list_uniq(make_list("/yabb", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 url = string(dir, "/YaBB.pl");
 r = http_send_recv3(method: "GET", item:url, port:port);
 if( isnull(r) ) exit(0);
 if(egrep(pattern:"Powered by.*YaBB 1 Gold - (Release|SP1(\.[1-2].*|3(\.1)?))", string: r[2]))
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
