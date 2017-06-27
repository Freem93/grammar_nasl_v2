#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17308);
 script_cve_id("CVE-2005-0694");
 script_bugtraq_id(12748);
 script_osvdb_id(14603);

 script_version("$Revision: 1.13 $");
 script_name(english:"Hosting Controller HCDiskQuoteService.csv Direct Request Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be prone to an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Hosting Controller a web hosting management
application. 

The remote version of this software is vulnerable to an information
disclosure flaw which may allow an attacker to gather additional data
on the remote host. 

An attacker may download the file 'HCDiskQuotaService.csv'
and gain the list of hosted domains." );
 script_set_attribute(attribute:"solution", value:
"Block access to the file 'HCDiskQuoteService.csv'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/07");
 script_cvs_date("$Date: 2011/03/14 21:48:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Downloads HCDiskQuoteService.csv";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function check(dir, port)
{
  local_var	u, r, buf, rep;
  u = dir + "/logs/HCDiskQuotaService.csv";
  r = http_send_recv3(method:"GET", port:port, item:u);
  if(isnull(r))exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);
  if ("Date,Time,Action,Comments," >< buf )
  	{
	rep = 'The vulnerable file was found under :\n' + u;
	security_warning(port:port, extra: rep);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);
foreach dir (cgi_dirs()) check( dir : dir, port : port);
