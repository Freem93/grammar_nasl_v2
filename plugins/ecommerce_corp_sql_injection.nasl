#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(12062);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2004-0300", "CVE-2004-0301");
  script_bugtraq_id(9676, 9687);
  script_osvdb_id(3973, 4538, 15446, 15447, 15448);

  script_name(english:"Ecommerce Corp. Online Store Kit 3.0 Multiple Vulnerabilities");
  script_summary(english:"More.php MoSQL Injection");
 
  script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has a SQL injection
vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The remote host is running Ecommerce Corporation Online Store Kit, a
web-based e-commerce CGI suite.

There is a SQL injection vulnerability in the 'id' parameter of
'more.php'.  This could allow a remote attacker to execute arbitrary
SQL commands, which could be used to take control of the database.
Additional vulnerabilities have been reported in various
scripts, though Nessus has not tested for them."  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to the latest version of this software."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/17");
 script_cvs_date("$Date: 2015/02/02 19:32:50 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port))exit(0);

function check_dir(path)
{
 local_var req, res;

 req = string(path, "/more.php?id=1'");
 res = http_send_recv3(method:"GET", item:req, port:port);
 if (isnull(res)) exit(0);

 if ( "SELECT catid FROM catlink WHERE prodid=1" >< res[2] )
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);  
  exit(0);
 }
}

foreach dir (cgi_dirs())
 {
 	check_dir(path:dir);
 }
