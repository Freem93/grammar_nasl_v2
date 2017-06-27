#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51861);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2011-0017");
  script_bugtraq_id(46065);
  script_osvdb_id(70696);

  script_name(english:"Exim < 4.74 Local Privilege Escalation");
  script_summary(english:"Checks version of SMTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a local privilege
escalation vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Exim, a message transfer agent.

According to the version number in its banner, the installed version
of Exim is earlier than 4.74 and thus potentially affected by a local
privilege escalation vulnerability.

If the remote host is running Linux, attackers can exploit this issue
to append arbitrary data to files through symbolic link attacks.
Successfully exploiting this issue allows local attackers with 'exim'
run-time user privileges to perform certain actions with superuser
privileges, leading to a complete compromise of an affected computer.");

  script_set_attribute(attribute:"see_also", value:"ftp://ftp.exim.org/pub/exim/ChangeLogs/ChangeLog-4.74");
  script_set_attribute(attribute:"see_also", value:"http://lists.exim.org/lurker/message/20110126.034702.4d69c278.en.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Exim 4.74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "SMTP/exim");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the banner from the SMTP server listening on port "+port+".");
if ("Exim" >!< banner) exit(0, "The banner from the SMTP server listening on port "+port+" is not from Exim.");

matches = eregmatch(pattern:"220.*Exim ([0-9\.]+)", string:banner);
if (isnull(matches)) exit(1, "Failed to determine the version of Exim based on the banner from the SMTP server listening on port "+port+".");

version = matches[1];
if (ereg(pattern:"^([0-3]\.|4\.([0-9]|[0-6][0-9]|7[0-3])$)", string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Banner            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.74';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Exim version "+version+" is running on the port "+port+" and not affected.");
