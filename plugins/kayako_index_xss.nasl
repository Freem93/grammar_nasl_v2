#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17598);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_cve_id("CVE-2005-0842");
  script_bugtraq_id(12868);
  script_osvdb_id(14963);

  script_name(english:"Kayako eSupport Troubleshooter Module index.php Multiple Parameter XSS");
  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in Kayako eSupport's index.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
several cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Kayako eSupport installed on the remote host is subject
to multiple cross-site scripting vulnerabilities in the script
'index.php' through the parameters '_i' and '_c'.  These issues may
allow an attacker to inject HTML and script code into a user's browser
within the context of the remote site, enabling him to steal
authentication cookies, access data recently submitted by the user,
and the like.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393946");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8313f62");
  script_set_attribute(attribute:"solution", value:"Upgrade to eSupport 2.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kayako:esupport");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, php:TRUE);
if ( get_kb_item("www/" + port + "/generic_xss") )
  exit(1, "The server listening on port "+port+" is affected by a generic cross-site-scripting vulnerability.");

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
exss = urlencode(str:xss);

# Try the exploit.
affected = test_cgi_xss(port: port, cgi: "/index.php", dirs: cgi_dirs(),
 pass_str: xss, 
 qs: strcat("_a=knowledgebase&",
    	    "_j=questiondetails&",
	    "_i=[1]['%3e", exss, "]") );

if (!affected)
  exit(0, "No affected URLs were found on port "+port+".");
