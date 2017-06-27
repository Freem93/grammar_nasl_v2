#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69018);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_cve_id("CVE-2013-3564");
  script_bugtraq_id(60705);
  script_osvdb_id(94139);

  script_name(english:"VLC Web Interface XML Services XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VLC media player install on the remote host is affected by a
cross-site scripting vulnerability because it fails to sanitize input
passed via XML services in the web interface. 

Note that the install is likely to be affected by additional
vulnerabilities as well, although Nessus has not tested for these
issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.7.html");
  script_set_attribute(attribute:"see_also", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2013-007.txt");
  # http://blog.spiderlabs.com/2013/06/twsl2013-006-cross-site-scripting-vulnerability-in-coldbox.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f33883d");
  script_set_attribute(attribute:"solution", value:"Upgrade to VLC 2.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("vlc_web_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/VLC/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:8080);
appname = "VLC media player";

installed = get_kb_item("www/VLC/installed");
if (isnull(installed)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

install_url = build_url(port:port, qs:"/");
acl = get_kb_item("www/VLC/" + port + "/acl");
if (acl) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);

xss_test = "'<a xmlns:nessus='http://www.w3.org/1999/xhtml'><nessus:body onload='alert(" + '"' + SCRIPT_NAME + '-' + unixtime() + '"' + ")'/></a>";
exploit = test_cgi_xss(
  port  : port,
  dirs  : make_list(""),
  cgi   : '/requests/vlm_cmd.xml',
  qs    : 'command=' + SCRIPT_NAME + urlencode(str:xss_test),
  pass_str : xss_test,
  pass_re  : 'Incomplete command :'
);
if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);

