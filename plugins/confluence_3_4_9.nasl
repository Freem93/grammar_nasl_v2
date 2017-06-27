#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53576);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_bugtraq_id(47398);
  script_osvdb_id(71901, 71902);
  script_xref(name:"Secunia", value:"44194");
  script_xref(name:"Secunia", value:"44204");

  script_name(english:"Atlassian Confluence 2.x >= 2.7 / 3.x < 3.4.9 Multiple XSS");
  script_summary(english:"Checks the Atlassian Confluence version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple cross-site
scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian Confluence on the remote host is a 2.x version that is 2.7
or later, or else version 3.x prior to 3.4.9. It is, therefore,
affected by multiple cross-site scripting vulnerabilities.

Errors in the validation of input data to certain macros allow
unfiltered data to be returned to a user's browser. The affected
macros are: Include Page, Activity Stream, Action links of attachments
lists and Table of Contents.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");

  # https://confluence.atlassian.com/display/DOC/Confluence+Security+Advisory+2011-03-24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?258e5e82");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21604");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21606");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21766");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-21819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Confluence version 3.4.9 or later, or apply the appropriate
vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("confluence_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/confluence", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

install = get_install_from_kb(
  appname      :'confluence',
  port         :port,
  exit_on_fail :TRUE
);

dir     = install['dir'];
version = install['ver'];
install_url = build_url(port:port, qs:dir);

if (isnull(version) || version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Confluence", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ '^3(\\.4)?$')
{
  gran = FALSE;
  # Check build (if we have it) to see if we do indeed have version 3.4
  # or if our version is not granular enough. Build info can be found at
  # https://developer.atlassian.com/display/CONFDEV/Confluence+Build+Information
  build = get_kb_item("www/" +port+ "/confluence/build/" + dir);
  if (build != UNKNOWN_VER)
  {
    if (build == "2029") gran = TRUE;
  }
  if (!gran)
    audit(AUDIT_VER_NOT_GRANULAR, "Confluence", port, version);
}

ver = split(version,sep:'.', keep:FALSE);
  for (x=0; x<max_index(ver); x++)
    ver[x] = int(ver[x]);

# Affects:
# 2.7 - 3.4.8
if (
  (ver[0] == 2 && ver[1] >= 7) ||
  (
    ver[0] == 3 &&
    (
      ver[1] < 4 ||
      (ver[1] == 4 && ver[2] < 9)
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
      '\n  Fixed version     : 3.4.9' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Confluence", install_url, version);
