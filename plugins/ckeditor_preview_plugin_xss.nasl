#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76943);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2014-5191");
  script_bugtraq_id(69161);
  script_osvdb_id(109500);
  script_xref(name:"IAVA", value:"2014-A-0116");

  script_name(english:"CKEditor Preview Plugin Unspecified XSS");
  script_summary(english:"Looks for patched Preview plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CKEditor installed on the remote host is affected by a
cross-site scripting vulnerability.

The included 'Preview' plugin fails to properly sanitize user-supplied
input. A remote, unauthenticated attacker can leverage this issue to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://ckeditor.com/blog/CKEditor-4.4.3-Released");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ckeditor:ckeditor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(
  make_list(
    "/ckeditor",
    "/modules/ckeditor",
    "/admin/ckeditor",
    "/includes/ckeditor",
    "/lib/ckeditor",
    cgi_dirs()
  )
);
else dirs = make_list(cgi_dirs());

install_dirs = make_list();
non_vuln = make_list();
vuln = 0;

foreach dir (dirs)
{
  # check that preview plugin is installed
  # exists in full versions, is not included in standard installs, but can be
  # installed to them.
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/plugins/preview/preview.html",
    exit_on_fail : TRUE
  );

  if (
    "var doc = document" >< res[2] &&
    "window.opener._cke_htmlToLoad" >< res[2]
  )
  {
    install_dirs = make_list(install_dirs, dir);
    # Check for patch
    if ("typeof window.opener._cke_htmlToLoad == 'string'" >!< res[2])
    {
      vuln++;
      set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
      if (report_verbosity > 0)
      {
        report =
        '\n' + 'Nessus was able to verify the issue by examining the output from the' +
        '\n' + 'following request :' +
        '\n' +
        '\n' + build_url(qs:dir + "/plugins/preview/preview.html", port:port) +
        '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }
    else non_vuln = make_list(non_vuln, build_url(qs:dir, port:port));
    if (!thorough_tests && vuln) break;
  }
}

if (max_index(install_dirs) == 0) exit(0, "The Preview plugin for CKEditor was not located on the web server on port " + port + ".");

if (vuln) exit(0);   # nb: if vuln, a report was already issued.

# Audit Trails
installs = max_index(non_vuln);
if (installs > 0)
{
  if (installs == 1)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, "CKEditor", non_vuln[0]);
  else exit(0, "The CKEditor installs at " + join(non_vuln, sep:", ") +
    " are not affected.");
}
