#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11766);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
 script_bugtraq_id(7980, 7981);
 script_osvdb_id(54724, 54725, 54726);

 script_name(english:"pMachine <= 2.2.1 Multiple Vulnerabilities");
 script_summary(english:"Checks for the presence of search/index.php");

 script_set_attribute(attribute:"synopsis", value:"A remote CGI is vulnerable to several flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of pMachine that is affected by 
two flaws : 

  - It is vulnerable to multiple path disclosure problems
    that could allow an attacker to gain more knowledge 
    about this host.

 - It is vulnerable to a cross-site-scripting attack that
   could allow an attacker to steal the cookies of the 
   legitimate users of this service.");
 script_set_attribute(attribute:"solution", value:"None at this time. Disable this CGI suite.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/19");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

test_cgi_xss(port: port, dirs: cgi_dirs(), cgi: "/search/index.php",
  qs: "weblog=nessus&keywords=<script>foo</script>",
  pass_str: "<script>foo</script>");
