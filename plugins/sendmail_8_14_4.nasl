#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43637);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/08/11 17:08:53 $");

  script_cve_id("CVE-2009-4565");
  script_bugtraq_id(37543);
  script_osvdb_id(62373);
  script_xref(name:"IAVA", value:"2010-A-0002");
  script_xref(name:"Secunia", value:"37998");

  script_name(english:"Sendmail < 8.14.4 SSL Certificate NULL Character Spoofing");
  script_summary(english:"Checks the version of Sendmail");

  script_set_attribute(attribute:"synopsis", value:"The remote mail server is susceptible to a man-in-the-middle attack.");
  script_set_attribute(attribute:"description", value:
"The remote mail server is running a version of Sendmail earlier than
8.14.4. Such versions are reportedly affected by a flaw that may allow
an attacker to spoof SSL certificates by using a NULL character in
certain certificate fields.

A remote attacker may exploit this to perform a man-in-the-middle
attack.");
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.14.4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.14.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if (!get_port_state(port))  exit(0, "Port "+port+" is not open.");

banner = get_smtp_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the SMTP server's banner on port "+ port +".");
if (!ereg(pattern:"[Ss]endmail ",string:banner))  exit(0, "The SMTP server's banner on port "+ port + " is not from Sendmail.");

matches = eregmatch(pattern:"[Ss]endmail[^0-9/]*([0-9.]+)",string:banner);
if (isnull(matches)) exit(1, "Failed to determine the version of Sendmail based on the banner from port "+ port +".");
version = matches[1];

if(ereg(pattern:"^([0-7]\.|8\.([0-9]($|[^0-9])|1[0-3]($|[^0-9])|14($|\.[0-3]($|[^0-9]))))",string:version))
{
  if(report_verbosity > 0)
  {
    report = '\n' +
             'Sendmail version '+ version + ' appears to be running on the remote host based\n' +
             'on the following banner :\n' +
             '\n' +
             '  ' + banner + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else
  exit(0,"The version of Sendmail listening on port "+port+" is not affected since it is version "+version+".");
