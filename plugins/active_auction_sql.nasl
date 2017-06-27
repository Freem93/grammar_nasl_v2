#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17989);
 script_cve_id("CVE-2005-1029", "CVE-2005-1030");
 script_bugtraq_id(13039, 13038, 13036, 13035, 13034, 13032);
 script_osvdb_id(15281, 15282, 15283, 15284, 15285, 15286, 15287);

 script_version("$Revision: 1.17 $");
 script_name(english:"Active Auction Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server contains a ASP script that is affected by various
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Active Auction, an auction software written
in ASP. 

The remote version of this software is affected by various SQL
injection and cross-site scripting issues." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/85");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/05");
 script_cvs_date("$Date: 2016/09/23 20:00:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for a SQL injection error in Active Auction House";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (make_list( cgi_dirs()))
{
 r = http_send_recv3(method:"GET",item:dir + "/activeauctionsuperstore/ItemInfo.asp?itemID=42'", port:port);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);

 if(egrep(pattern:"Microsoft.*ODBC.*80040e14", string:res ) )
  {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
  }
}
