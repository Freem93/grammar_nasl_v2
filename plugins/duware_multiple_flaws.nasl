#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(15453);
 script_cve_id("CVE-2004-2198", "CVE-2004-2199", "CVE-2004-2200", "CVE-2004-2201", "CVE-2004-2202");
 script_bugtraq_id(11363);
 script_osvdb_id(10663, 10664, 10665, 10666, 10667, 10668, 10669, 19198);
 script_version ("$Revision: 1.16 $");

 script_name(english:"DUware Products Multiple Remote Vulnerabilities (SQLi, XSS)");
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a product published by DUware - either
DUclassmate, DUclassified or DUforum.

There is a flaw in the remote version of this software that could allow
an attacker to execute arbitrary SQL statements on the remote host by
supplying malformed values to the arguments of /admin/, messages.asp or
messagesDetails.asp.

In addition, DUclassified contains a cross-site scripting vulnerability
in Message Text handling. DUclassmate contains an unauthorized password 
manipulation issue in account.asp." );
 script_set_attribute(attribute:"solution", value:
"Upgrade the newest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/11");
 script_cvs_date("$Date: 2014/05/21 20:41:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if the remote ASP scripts are vulnerable to SQL injection"); 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_asp(port:port))exit(0);

urls = make_list("/index.asp?user='", "messageDetail.asp?MSG_ID='");
foreach d (cgi_dirs())
{
 foreach url (urls) 
 {
 r = http_send_recv3(method: "GET", item: d + url, port:port);
 if ( isnull(r) ) exit(0);
 if ("Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< r[2] )
  {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
  }
 }
}
