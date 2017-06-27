#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16174);
  script_version("$Revision: 1.17 $");
  script_bugtraq_id(12310);
  script_osvdb_id(13134, 13135);
  
  script_name(english:"Novell GroupWise 6.5.3 WebAccess Multiple XSS");
  script_summary(english:"Checks GroupWare XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple cross-site scripting vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Novell GroupWise WebAccess, a commercial
groupware package.

The remote version of this software is affected by multiple cross-site
scripting flaws due to a lack of sanitization of user-supplied data.

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user." );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jan/626" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/18");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

r = http_send_recv3(method:"GET",item:"/servlet/webacc?User.lang=<script>foo</script>", port:port);
if( r == NULL )exit(0);

if("/com/novell/webaccess/images/btnlogin<script>foo</script>.gif" >< r[2] )
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
