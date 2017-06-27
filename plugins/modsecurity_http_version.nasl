#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67123);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/02 15:43:32 $");

  script_name(english:"ModSecurity Version");
  script_summary(english:"Obtains the version of the remote ModSecurity Install");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote ModSecurity
install.");
  script_set_attribute(attribute:"description", value:
"Based on HTTP headers, the remote host appears to be running
ModSecurity, an open source web application firewall (WAF).  It was
possible to read the version number from the banner.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modsecurity:modsecurity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("waf_detection.nbin");
  script_require_keys("www/ModSecurity");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var port, src, ver;

function parse_banner(headers)
{
  local_var item, match, matches, pattern, patterns;

  src = NULL;
  ver = NULL;

  patterns = make_list(
    '^Server:.*[Mm]od_?[Ss]ecurity2?/([0-9]+(\\.[^ ]+)?)',
    '^Server:.*[Mm]od_?[Ss]ecurityPHP/([0-9]+(\\.[^ ]+)?)',
    '^Server:.*[Mm]od[_ ]?[Ss]ecurity ([0-9]+(\\.[^ ]+)?)'
  );

  foreach pattern (patterns)
  {
    matches = egrep(pattern:pattern, string:headers);
    if (strlen(matches) > 0) break;
  }

  # If no matches, just return; we won't get src and ver
  if (strlen(matches) == 0) return;

  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pattern, string:match);
    if (!isnull(item))
    {
      src = item[0];
      ver = item[1];
      break;
    }
  }
}

# May fork
port = get_kb_item_or_exit("www/waf/ModSecurity");

# Get pristine banner.
pristine = get_http_banner(port:port, exit_on_fail:TRUE);

# Ensure that the banner is usable.
if ("Server:" >!< pristine)
  audit(AUDIT_WRONG_WEB_SERVER, port, "one that provides a Server response header.");

if (egrep(pattern:"^Server:.*[Mm]od[_ ]?[Ss]ecurity", string:pristine))
  modsecurity_installed = TRUE;
else
  audit(AUDIT_WEB_APP_NOT_INST, "ModSecurity", port);

# Set a KB item so that we know it's ModSecurity on a certain port
set_kb_item(name:"www/" + port + "/modsecurity", value:TRUE);

# Parse the pristine banner.
parse_banner(headers:pristine);

if (isnull(src)) audit(AUDIT_WEB_APP_NOT_INST, "ModSecurity", port);
set_kb_item(name:"www/modsecurity/" + port + "/pristine/source", value:src);

if (isnull(ver)) ver = 'unknown';
set_kb_item(name:"www/modsecurity/" + port + "/pristine/version", value:ver);
orig_ver = ver;
orig_src = src;

# Parse backported banner.
banner = get_backport_banner(banner:pristine);
parse_banner(headers:banner);

if (isnull(src)) audit(AUDIT_WEB_APP_NOT_INST, "ModSecurity", port);
set_kb_item(name:"www/modsecurity/" + port + "/source", value:src);
set_kb_item(name:"www/modsecurity/" + port + "/backported", value:backported);

if (isnull(ver)) ver = 'unknown';
set_kb_item(name:"www/modsecurity/" + port + "/version", value:ver);
report_source = src;
report_version = ver;

# Report findings
if (modsecurity_installed)
{
  if (report_paranoia < 2 && backported)
  {
    report_backported_note =
      '  Note    : This install may have backported patches and thus,' +
      '\n            version checks will not be run in non-paranoid scan modes.' +
      '\n';

    # Use originally detected version in report for
    # non-paranoid scans
    report_version = orig_ver;
    report_source = orig_src;
  }

  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus found the following version information in the HTTP Server header :' +
      '\n' +
      '\n  Source  : ' + report_source +
      '\n  Version : ' + report_version +
      '\n';
    if (!isnull(report_backported_note))
      report = report + report_backported_note;
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
