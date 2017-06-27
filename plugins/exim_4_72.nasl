#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46783);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/25 23:51:31 $");

  script_cve_id("CVE-2010-2023", "CVE-2010-2024");
  script_bugtraq_id(40451, 40454);
  script_osvdb_id(65158, 65159);
  script_xref(name:"Secunia", value:"40019");

  script_name(english:"Exim < 4.72 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SMTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Exim, a message transfer agent (SMTP).

According to the version number in its banner, the installed version
of Exim is earlier than 4.72 and thus potentially affected by one or
both of the following vulnerabilities :

  - An error when handling hardlinks within the mail
    directory during the mail delivery process can be
    exploited to perform unauthorized actions.
    (CVE-2010-2023)

  - When MBX locking is enabled, a race condition exists
    that could allow an attacker to change permissions of
    other non-root users' files, leading to denial-of-
    service conditions or potentially privilege escalation.
    (CVE-2010-2024)");
  script_set_attribute(attribute:"see_also", value:"http://lists.exim.org/lurker/message/20100524.175925.9a69f755.en.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f28f03db");
  script_set_attribute(attribute:"see_also", value:"http://bugs.exim.org/show_bug.cgi?id=988");
  script_set_attribute(attribute:"see_also", value:"http://bugs.exim.org/show_bug.cgi?id=989");
  script_set_attribute(attribute:"solution", value:"Upgrade to Exim 4.72 or later when it becomes available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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
if (ereg(pattern:"^([0-3]\.|4\.([0-9]|[0-6][0-9]|7[01])$)", string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Banner            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.72';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Exim version "+version+" is running on the port "+port+" and not affected.");
