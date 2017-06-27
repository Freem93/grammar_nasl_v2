#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71213);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_bugtraq_id(61135, 61170);
  script_osvdb_id(95114, 95115, 95116);

  script_name(english:"Atlassian Confluence < 4.3.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the Atlassian Confluence version.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian Confluence on the remote host is a version prior to 4.3.7.
It is, therefore, affected by multiple vulnerabilities :

  - A clickjacking vulnerability exists due to the lack of
    iframe busting prevention. An attacker may exploit this
    to perform a limited amount of actions on the user's
    behalf.

  - The application does not properly check user uploaded
    files. By uploading a flash file, a remote attacker can
    place the file in a user-accessible path. A subsequent
    direct request to the file could allow the attacker to
    execute a script with the privileges of the web server.

  - A cross-site scripting flaw exists because the
    application does not properly check uploaded file
    attachments to a wiki page. By uploading a specially
    crafted file, an attacker could execute arbitrary
    script within the browser / server trust relationship.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");

  # http://www.baesystemsdetica.com.au/Research/Advisories/Atlassian-Confluence-Multiple-Vulnerabilities-(DS-
  # The above link has gone stale, and the web page had to be retrieved from web.archive.org instead
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?905431b7");
  # https://confluence.atlassian.com/display/DOC/Confluence+4.3.7+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd17669f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Confluence version 4.3.7 or later, or apply the appropriate
vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("confluence_detect.nasl");
  script_require_ports("Services/www", 8080, 8090);
  script_require_keys("www/confluence", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8090);

install = get_install_from_kb(
  appname      :'confluence',
  port         :port,
  exit_on_fail :TRUE
);

dir     = install['dir'];
version = install['ver'];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Confluence", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ '^4(\\.3)?$')
{
  gran = FALSE;
  # Check build (if we have it) to see if we do indeed have version 4.3
  # or if our version is not granular enough. Build info can be found at
  # https://developer.atlassian.com/display/CONFDEV/Confluence+Build+Information
  build = get_kb_item("www/" +port+ "/confluence/build/" + dir);

  if (build != UNKNOWN_VER)
  {
    if (build == "3388") gran = TRUE;
  }
  if (!gran)
    audit(AUDIT_VER_NOT_GRANULAR, "Confluence", port, version);
}

# Affects versions < 4.3.7
fix_ver = '4.3.7';
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_ver + 
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Confluence", install_url, version);
