#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if (description)
{
 script_id(15626);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2015/01/23 22:03:55 $");

 script_cve_id("CVE-2004-1101");
 script_bugtraq_id(11596);
 script_osvdb_id(11412);
 script_xref(name:"CERT", value:"107998");
 script_xref(name:"Secunia", value:"13093");

 script_name(english:"TIPS MailPost append Parameter XSS");
 script_summary(english:"Test the remote mailpost.exe");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a cross-site scripting
vulnerability.");
 script_set_attribute(attribute:"description", value:
"TIPS MailPost, a web application used for emailing HTML form data to a
third party, is installed on the remote host. 

The version of MailPost hosted on the remote web server has a cross-site
scripting vulnerability in the 'append' variable of mailpost.exe when
debug mode is enabled.  Debug mode is enabled by default.  A remote
attacker could exploit this to impersonate legitimate users. 

This version of MailPost reportedly has other vulnerabilities, though
Nessus has not checked for those issues.");
 script_set_attribute(attribute:"solution", value:"Disable debug mode.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

test_cgi_xss(port: port, cgi: "/mailpost.exe", qs: "<script>foo</script>", 
  pass_str: "CGI_QueryString= <script>foo</script>");
