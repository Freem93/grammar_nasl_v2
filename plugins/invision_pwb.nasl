#
#  This script was rewritten by Tenable Network Security, using a new 
#  HTTP API, and modified to be compliant with the security advisory.
#
#  Ref: Alexander Antipov <Antipov SecurityLab ru>
#


include("compat.inc");

if(description) 
{ 
  script_id(15425); 
  script_version("$Revision: 1.20 $"); 

  script_cve_id("CVE-2004-1578");
  script_bugtraq_id(11332);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"10512");
      
  name["english"] = "Invision Power Board Referer field XSS"; 
        
  script_name(english:name["english"]); 

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The version of Invision Power Board installed on the remote host is
vulnerable to cross-site scripting attacks that could allow an attacker
to steal a user's cookies." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Oct/104" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
        
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/06");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();

        
  summary["english"] = "Checks for Invision Power Board XSS";
  script_summary(english:summary["english"]);
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
	
  script_dependencies("invision_power_board_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);
if (get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(0);

dir = matches[2];

test_cgi_xss(port: port, cgi: "/index.php", dirs: make_list(dir), 
 qs: "s=5875d919a790a7c429c955e4d65b5d54&act=Login&CODE=00",
 add_headers: make_array("Referer",  '"\'/><script>foo</script>'), 
 pass_re: '<input type="hidden" name="referer" value=".".\'/><script>foo</script>' );
