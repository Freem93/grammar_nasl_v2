#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62938);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(56141);
  script_osvdb_id(86499);
  script_xref(name:"EDB-ID", value:"22097");

  script_name(english:"Freestyle Support Portal Component for Joomla! 'prodid' Parameter SQLi");
  script_summary(english:"Checks version of Freestyle Support Portal Component.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Freestyle Support Portal component for Joomla!
running on the remote host is affected by a SQL injection
vulnerability in the index.php script due to improper sanitization of
user-supplied input to the 'prodid' parameter before using it to
construct database queries. An unauthenticated, remote attacker can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, modification of data, or other
attacks against the underlying database.

Note that Nessus has not tested for this issue but has instead relied
on the component's self-reported version number.");
  # https://web.archive.org/web/20130227001038/http://freestyle-joomla.com/help/announcements?announceid=60
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?811ad44e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Freestyle Support Portal version 1.9.2.1484 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
loc =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "Freestyle Support Portal";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('function fss_remove_comment');
  checks["/components/com_fss/assets/js/comments.js"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, loc, plugin + " component");

files = make_list("com_fss.xml", "fss.xml");
version = NULL;

foreach file (files)
{
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : dir + "/administrator/components/com_fss/" + file,
    exit_on_fail : TRUE
  );

  tag = "<version>(.+)</version>";

  if ("<description>Freestyle Support Portal" >< res[2])
  {
    matches = egrep(pattern:tag, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
     {
       item = eregmatch(pattern:tag, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }
  }
  # fss.xml was introduced in later versions. We want this version to compare
  # to the patched version in the event that both files exist
  if (file == "fss.xml") break;
}
if (empty_or_null(version))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "the " + plugin+ " component for " + app, loc);

# Versions are listed as x.x.x.x (ie 1.9.2.1484) in the fss.xml file
# or listed as x.x.x (ie 1.5.6) in com_fss.xml
ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions < 1.9.2.1484 are affected
if (
  (ver[0] < 1) ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 9 ||
      (
        ver[1] == 9 &&
        (
          ver[2] < 2 ||
          (ver[2] == 2 && ver[3] < 1484)
        )
      )
    )
  )
)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], loc,
    order[1], version,
    order[2], '1.9.2.1484'
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(
    port     : port,
    extra    : report,
    severity : SECURITY_HOLE,
    sqli     : TRUE
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, loc, plugin + " component", version);
