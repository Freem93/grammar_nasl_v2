#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17724);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2006-4434");
  script_bugtraq_id(19714);
  script_osvdb_id(28193);

  script_name(english:"Sendmail < 8.13.8 Header Processing Overflow DoS");
  script_summary(english:"Checks the version of Sendmail.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is susceptible to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The remote mail server is running a version of Sendmail earlier than
8.13.8.  Such versions are reportedly affected by a use-after-free
flaw that may allow an attacker to crash the server.");

  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.13.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.13.8.php");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2)
  exit(0, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

# Get banner for service.
banner = get_smtp_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the banner from the SMTP server listening on port " + port + ".");

# Get backported version of the banner.
bp_banner = tolower(get_backport_banner(banner:banner));
if (bp_banner !~ "[Ss]endmail ") exit(0, "The banner from the SMTP server listening on port " + port + " is not from Sendmail.");
if (backported) exit(1, "The banner from the sendmail server listening on port " + port + " indicates patches may have been backported.");

# Extract version number from banner.
matches = eregmatch(pattern:"[Ss]endmail[^0-9/]*([0-9.]+)", string:bp_banner);
if (isnull(matches)) exit(1, "Failed to determine the version of sendmail based on the banner from port " + port + ".");
version = matches[1];

fixed = "8.13.8";
if (ver_compare(ver:version, fix:fixed) >= 0)
  exit(0, "The sendmail "+version+" server listening on port "+port+" is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
