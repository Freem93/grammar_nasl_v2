#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69804);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/12 18:47:27 $");

  script_bugtraq_id(61626);
  script_osvdb_id(96003);

  script_name(english:"Atlassian Confluence < 5.1.5 OGNL Expression Handling Double Evaluation Error Remote Code Execution");
  script_summary(english:"Checks the Atlassian Confluence version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian Confluence on the remote host is a version prior to 5.1.5.
It is, therefore, affected by a remote code execution vulnerability
due to a flaw in the handling of OGNL expressions. This could allow an
attacker to execute arbitrary Java code on the remote host.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");

  # https://confluence.atlassian.com/display/DOC/Confluence+Security+Advisory+2013-08-05
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?396c4ca3");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-30221");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Confluence version 5.1.5 or later, or apply the appropriate
vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

if (version =~ '^5(\\.1)?$')
{
  gran = FALSE;
  # Check build (if we have it) to see if we do indeed have version 5.1
  # or if our version is not granular enough. Build info can be found at
  # https://developer.atlassian.com/display/CONFDEV/Confluence+Build+Information
  build = get_kb_item("www/" +port+ "/confluence/build/" + dir);
  if (build != UNKNOWN_VER)
  {
    if (build == "4215") gran = TRUE;
  }
  if (!gran) audit(AUDIT_VER_NOT_GRANULAR, "Confluence", port, version);
}

fix_ver = '5.1.5';

# Affects versions < 5.1.5
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_ver + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Confluence", install_url, version);
