#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15987);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2004-1407", "CVE-2004-1408", "CVE-2004-1409");
 script_bugtraq_id(11990);
 script_osvdb_id(12569, 12570, 12571, 12572, 12573);
 
 script_name(english:"Singapore Gallery < 0.9.11 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis",value:
"The remote web server contains a PHP script that is affected by
multiple vulnerabilities." );
 script_set_attribute( attribute:"description", value:
"Singapore is a PHP based photo gallery web application.

The remote version of this software is affected by multiple
vulnerabilities that may allow an attacker to read arbitrary
files on the remote host or to execute arbitrary PHP commands." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2004/Dec/209"
  );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.nessus.org/u?78dc82b5"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to Singapore 0.9.11 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/16");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"The presence of Singapore Gallery");
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, php: 1);

foreach dir (cgi_dirs())
{
 buf = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

 if(egrep(pattern:"Powered by.*singapore\..*singapore v0\.([0-8]\.|9\.([0-9][^0-9]|10))", string:buf) )
	{
 	security_warning(port);
	exit(0);
	}
}
