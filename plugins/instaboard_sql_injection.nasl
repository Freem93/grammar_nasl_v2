#
# (C) Tenable Network Security, Inc.
#

# Ref: 
#  Date: Mon, 14 Apr 2003 12:34:54 -0400
#  From: Jim Dew <jdew@cleannorth.org>
#  To: bugtraq@securityfocus.com
#  Subject: Instaboard 1.3 SQL Injection


include("compat.inc");

if(description)
{
 script_id(11532);
 script_version ("$Revision: 1.16 $");

 script_bugtraq_id(7338);
 script_osvdb_id(51271);
 
 script_name(english:"Instaboard index.cfm Multiple Parameter SQL Injection");
 script_summary(english:"Checks for SQL insertion in Instaboad");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote server is running NetPleasure's Instaboard.

There is a bug in this release which allow an attacker to perform
a SQL injection attack through the page 'index.cfm'.

An attacker may use this flaw to gain unauthorized access to take
the control of the remote database." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/14");
 script_cvs_date("$Date: 2012/05/31 21:25:30 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = make_list(cgi_dirs(), "/instaboard");

foreach d (dirs)
{
 res = http_send_recv3(method:"GET", item:string(d, "/index.cfm?catid=1%20SQL"), port:port);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

 if("[Microsoft][ODBC SQL Server Driver][SQL Server]" >< res[2])
 {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
 }
}
