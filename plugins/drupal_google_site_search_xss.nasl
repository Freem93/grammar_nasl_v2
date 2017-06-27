#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70920);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/03 13:28:13 $");

  script_cve_id("CVE-2013-4384");
  script_bugtraq_id(62495);
  script_osvdb_id(97503);

  script_name(english:"Drupal Google Site Search Module API Data Handling XSS");
  script_summary(english:"Checks the version of the Google Site Search module.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts a version of the Google Site Search module
for Drupal that is version 6.x prior to 6.x-1.4 or 7.x prior to
7.x-1.10. It is, therefore, affected by a cross-site scripting
vulnerability due to a failure to properly sanitize API data before
returning it to a user. This allows a remote, unauthenticated
attacker, via a specially crafted request to execute arbitrary script
code in a user's browser to be executed within the security context of
the affected site. 

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"https://drupal.org/node/2092395");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Site Search version 6.x-1.4 / 7.x-1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google_site_search_project:google_site_search_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/Drupal");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
app_ver = install["version"];
url = build_url(qs:dir, port:port);

# Affected module versions only exist for versions 6 and 7 of Drupal
if (app_ver !~ "^(6|7)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, app_ver);

found = FALSE;
module = "Google Site Search module";
vuln = FALSE;
version = UNKNOWN_VER;
disp_ver = UNKNOWN_VER;

# Try and get path to module from index
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/index.php",
  exit_on_fail : TRUE
);

# Versions 7.x
pat = "(/sites/.*/modules/.*/gss/)scripts/autocomplete\.js";
if (egrep(pattern:pat, string:res[2]))
{
  match = eregmatch(pattern:pat, string:res[2]);
  if (!isnull(match)) link = match[1];
}
# 6.x
else link = "/sites/all/modules/gss/";

# verify that the module is present
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + link + "gss.css",
  exit_on_fail : TRUE
);
if (".google-search-results" >< res[2]) found = TRUE;

if (!found)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, "Drupal", url, module);

# Grab version from our link
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + link + "gss.info",
  exit_on_fail : TRUE
);

if ("name = Google Site Search" >< res[2])
{
  pat1 = 'version = "([0-9]+\\.x-([0-9.]+))"';
  vermatch = eregmatch(pattern:pat1, string:res[2]);
  if (!isnull(vermatch))
  {
    version = vermatch[2];
    disp_ver = vermatch[1];
  }

  ver = split(version, sep:".", keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # 6.x-1.x < 6.x-1.4 are affected
  if (egrep(pattern:"core = 6\.x", string:res[2], icase:TRUE))
  {
    if (ver[0] == 1 && ver[1] < 4)
    {
      vuln = TRUE;
      fix = "6.x-1.4";
    }
  }
  # 7.x-1.x < 7.x-1.10 are affected
  else if (egrep(pattern:"core = 7\.x", string:res[2], icase:TRUE))
  {
    if (ver[0] == 1 && ver[1] < 10)
    {
      vuln = TRUE;
      fix = "7.x-1.10";
    }
  }
}

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "the " +module+ " for "+app, url);

if (vuln)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Module            : ' + module +
      '\n  Installed version : ' + disp_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, url, module);
