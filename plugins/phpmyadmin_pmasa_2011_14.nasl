#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56379);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_bugtraq_id(49648);
  script_osvdb_id(75449, 75450);

  script_name(english:"phpMyAdmin 3.4.x < 3.4.5 XSS (PMASA-2011-14)");
  script_summary(english:"Checks for unpatched JavaScript files in phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin on the remote host is 3.4.x prior to 3.4.5.
This version is affected by multiple cross-site scripting
vulnerabilities:

  - The data used in the row content display after inline
    editing is not properly sanitized before it is passed
    back to the browser.

  - The data passed in as table, column, and index names
    is not properly sanitized before it is passed back to
    the browser.

A remote attacker may use these issues to cause arbitrary code to be
executed in a user's browser, to steal authentication cookies and/or
to launch other types of attacks.");

  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-14.php");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor patches or upgrade to phpMyAdmin version 3.4.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port    = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);

ver = install['ver'];
dir = install['dir'];
unpatched_files = make_list();

# Get 'js/sql.js' and check for 'getFieldName'
# If present, version is in 3.4.x branch
url = dir + '/js/sql.js';
res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

if ('getFieldName' >!< res[2])
  exit(1, "The phpMyAdmin install at "+build_url(port:port,qs:dir)+" does not appear to contain version 3.4.x code and is therefore not affected.");

# Check for patched string in 'js/sql.js'
# If present, version is >= 3.4.5 (or is patched)
#   $this_sibling.html(k) < vuln    (as minimized JS; is '.html(new_html)' in raw)
#   $this_sibling.text(k) < patched (as minimized JS; is '.text(new_html)' in raw)
if (
  '$this_sibling.html(k)' >< res[2] &&
  '$this_sibling.text(k)' >!< res[2]
) unpatched_files = make_list(unpatched_files, url);

# Get 'js/functions.js' and check for 'escapeHtml' function
# and calls to this function.
# If present, version is >= 3.4.5 (or is patched)
url = dir + '/js/functions.js';
res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);
if (
  'escapeHtml' >!< res[2] &&
  'DROP DATABASE "+window.parent.db' >< res[2] &&
  'DROP DATABASE "+escapeHtml(window.parent.db)' >!< res[2]
) unpatched_files = make_list(unpatched_files, url);

# Get 'js/tbl_structure.js' and check for calls to 'escapeHtml' function
# If present, version is >= 3.4.5 (or is patched)
url = dir + '/js/tbl_structure.js';
res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);
if (
  'PMA_messages.strDoYouReally+" :\\n ALTER TABLE `"+a+"' >< res[2] &&
  'PMA_messages.strDoYouReally+" :\\n ALTER TABLE `"+escapeHtml(a)+"' >!< res[2]
) unpatched_files = make_list(unpatched_files, url);

if (max_index(unpatched_files) > 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      items   : unpatched_files,
      trailer : 'The listed URLs contain unpatched code and contribute to cross-site\n' +
                ' scripting vulnerabilities.',
      port    : port
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The phpMyAdmin install at "+build_url(port:port,qs:dir)+" is not affected.");
