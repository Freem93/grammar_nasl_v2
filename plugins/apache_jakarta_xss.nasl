#  
#  This script is written by shruti@tenablesecurity.com. 
#  based on work done by Renaud Deraison. 
#  Ref: Announced by vendor
#


include("compat.inc");

if(description)
{
 script_id(15908);
 script_version("$Revision: 1.22 $");
 script_bugtraq_id( 11803 );
 script_xref(name:"OSVDB", value:"12178");
 
 script_name(english:"Apache Jakarta Lucene results.jsp XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote Apache Jakarta Lucene software is vulnerable to a cross-
site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Apache Jakarta Lucene, a full-featured text 
search engine library implemented in Java.

There is a cross-site scripting vulnerability in the script
'results.jsp' that may allow an attacker to steal the cookies of
legitimate users on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Software Foundation Jakarta Lucene 1.4.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/25");
 script_cvs_date("$Date: 2015/08/04 20:57:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:jakarta_lucene");
script_end_attributes();

 
 script_summary(english:"Checks XSS in Apache Jakarta Lucene.");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP", "Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1, no_xss: 1);

test_cgi_xss( port: port, cgi: '/results.jsp', 
	      qs: 'query="><script>foo</script>"',
	      pass_str: "<script>foo</script>"  );
