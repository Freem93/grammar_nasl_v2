#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11764);
 script_version ("$Revision: 1.24 $");
 script_bugtraq_id(7969);
 script_xref(name:"OSVDB", value:"54805");
 
 script_name(english:"TMaxSoft JEUS url.jsp URI XSS");
 script_summary(english:"Checks for TMax Jeus");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has a cross-site
scripting vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running Tmax Soft JEUS, a web application
written in Java.

Input to the query string is not properly sanitized, which could
lead to a cross-site scripting attack.  A remote attacker could
exploit this by tricking a user into requesting a maliciously
crafted URL.  This would allow the attacker to impersonate the
targeted user." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2003/Jun/494"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/19");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

test_cgi_xss(port: port, cgi: "/url.jsp", dirs: cgi_dirs(), 
 qs: "<script>foo</script>", pass_re: "<script>foo</script>");
