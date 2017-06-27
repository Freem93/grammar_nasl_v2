#
# (C) Tenable Network Security, Inc.
#

# Ref :
#  Date: 1 Apr 2003 13:08:28 -0000
#  From: magistrat <magistrat@blocus-zone.com>
#  To: bugtraq@securityfocus.com
#  Subject: Css in Xoops module glossary 1.3.x

#
# This check will incidentally cover other flaws.


include("compat.inc");

if(description)
{
 script_id(11508);
 script_version ("$Revision: 1.23 $");
 script_bugtraq_id(7356);
 script_xref(name:"OSVDB", value:"53656");

 script_name(english:"XOOPS Glossary Module glossaire-aff.php lettre Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"There is a cross-site scripting issue in the version of XOOPS
installed on the remote host that may allow an attacker to steal your
user cookies.  The flaw lies in 'glossaire-aff.php'." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=104931621609932&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/03");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks for XOOPS");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("xoops_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/xoops");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 test_cgi_xss(port: port, dirs: make_list(d), cgi: "/modules/glossaire/glossaire-aff.php",
  qs: "lettre=<script>foo</script>", pass_str: "<script>foo</script>");
}
