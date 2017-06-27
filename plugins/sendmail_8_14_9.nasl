#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74289);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/04 11:16:55 $");

  script_cve_id("CVE-2014-3956");
  script_bugtraq_id(67791);
  script_osvdb_id(107311);

  script_name(english:"Sendmail < 8.14.9 close-on-exec SMTP Connection Manipulation");
  script_summary(english:"Checks Sendmail version");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an SMTP connection manipulation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote mail server is running a version of Sendmail prior to
8.14.9. It is, therefore, affected by a flaw related to file
descriptors and the 'close-on-exec' flag that may allow a local
attacker to cause unspecified impact on open SMTP connections.");
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.14.9");
  script_set_attribute(attribute:"see_also", value:"http://freecode.com/projects/sendmail/releases/363923");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.14.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

appname = "Sendmail";

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if (!ereg(pattern:"[Ss]endmail ",string:banner)) audit(AUDIT_NOT_LISTEN, appname, port);

matches = eregmatch(pattern:"[Ss]endmail[^0-9/]*([0-9.]+)",string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, appname, port);
version = matches[1];

# Affected :
# < 8.14.9
if (
  version =~ "^[0-7]\."
  ||
  version =~ "^8\.[0-9]($|[^0-9])"
  ||
  version =~ "^8\.1[0-3]($|[^0-9])"
  ||
  version =~ "^8\.14($|\.[0-8]($|[^0-9]))"
)
{
  if(report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Source            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.14.9' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
