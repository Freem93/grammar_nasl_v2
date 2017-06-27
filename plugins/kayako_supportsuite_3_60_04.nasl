#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40872);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2009-3427");
  script_osvdb_id(57009);
  script_xref(name:"Secunia", value:"36253");

  script_name(english:"Kayako SupportSuite Ticket Subject XSS");
  script_summary(english:"Checks version in banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by 
a persistent cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Kayako SupportSuite installed
on the remote host is earlier than 3.60.04.  Such versions are
affected by a persistent cross-site scripting vulnerability. 
Specifically, the installed version fails to sanitize input passed to
the subject field while creating a new support ticket.  An attacker
may be able to exploit this vulnerability by creating a new support
ticket with a specially crafted subject field, and inject arbitrary
HTML or script code into a user's browser which would get executed
every time the support ticket is viewed.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Aug/65");
   # http://web.archive.org/web/20091017194126/http://forums.kayako.com/f3/3-60-04-stable-available-now-23453/#post106727
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46f82a83");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kayako SupportSuite 3.60.04 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kayako:supportsuite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("kayako_supportsuite_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/kayako_supportsuite", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php: TRUE);

# Get installs
install = get_install_from_kb(appname:"kayako_supportsuite", port:port, exit_on_fail:TRUE);

dir         = install['dir'];
install_url = build_url(port:port,qs:dir);
version     = install['ver'];

if (version == UNKNOWN_VER || isnull(version))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "Kayako SupportSuite", install_url);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# nb: make sure we have at least three components since we're 
#     testing for 3 (might not be needed).
while (i < 3)
  ver[i++] = 0;

fixed_version = '3.60.04';

if (
  ver[0] < 3 ||
  (
    ver[0] == 3 &&
    (
      ver[1] < 60 ||
      (ver[1] == 60 && ver[2] < 4)
    )
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Kayako SupportSuite", install_url, version);
