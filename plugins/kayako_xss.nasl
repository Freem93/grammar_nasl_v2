#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16474);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/11/18 21:03:57 $");

  script_cve_id("CVE-2005-0487");
  script_bugtraq_id(12563);
  script_osvdb_id(12514, 13921);

  script_name(english:"Kayako eSupport index.php nav Parameter XSS");
  script_summary(english:"Determines the presence of Kayako eSupport");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a cross-
site scripting flaw.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Kayako eSupport, a web-based support and
help desk application. 

This version of eSupport is vulnerable to a cross-site scripting flaw
involving the 'nav' parameter of the 'index.php' script.  An attacker,
exploiting this flaw, would need to be able to coerce an unsuspecting
user into visiting a malicious website.  Upon successful exploitation,
the attacker would be able to steal credentials or execute browser-
side code.");
  script_set_attribute(attribute:"see_also", value:"http://forums.kayako.com/threads/esupport-security-vulnerabilities.2765/");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=full-disclosure&m=110845724029888&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kayako eSupport version 2.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:kayako:esupport");
  script_end_attributes();
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php:TRUE);
if ( get_kb_item("www/" + port + "/generic_xss") )
  exit(1, "The server listening on port "+port+" is affected by a generic cross-site-scripting vulnerability.");

affected = test_cgi_xss(
  port: port, 
  cgi: "/index.php", 
  qs: "_a=knowledgebase&_j=questiondetails&_i=2&nav=<script>alert(document.cookie)</script>",
  pass_str: "<script>alert(document.cookie)</script>"
);

if (!affected)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Kayako eSupport", build_url(port:port, qs:'/index.php'));
