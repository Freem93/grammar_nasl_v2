#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12096);
 script_cve_id("CVE-2004-1806");
 script_bugtraq_id(9854, 9856);
 script_osvdb_id(4229, 4230);
 script_xref(name:"Secunia", value:"11112");
 
 script_version("$Revision: 1.21 $");
 script_name(english:"cfWebStore Multiple Vulnerabilities (SQLi, XSS)");
 script_summary(english:"SQL Injection");
 
 script_set_attribute( attribute:"synopsis", value:
"The web application running on the remote host has multiple
vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running cfWebStore 5.0.0 or older.

There is a flaw in this software that could allow a remote attacker to
execute arbitrary SQL statements in the remote database that could in
turn be used to gain administrative access on the remote host, read,
or modify the content of the remote database.

Additionally, cfWebStore is reportedly vulnerable to a cross-site
scripting issue. However, Nessus has not tested for this." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Mar/120"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to cfWebStore version 5.0.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/12");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function check(dir)
{
  local_var buf, url;
  url = string(dir, "/index.cfm?fuseaction=category.display&category_ID='"); 
  buf = http_send_recv3(method:"GET", item:url, port:port);
  if(isnull(buf))exit(0);
  if ("cfquery name=&quot;request.QRY_GET_CAT&quot;" >< buf )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 return(0);
}

foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
