#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38877);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2009-1490");
  script_bugtraq_id(34944);
  script_osvdb_id(54669);

  script_name(english:"Sendmail < 8.13.2 Mail X-Header Handling Remote Overflow");
  script_summary(english:"Checks the version of Sendmail");

  script_set_attribute(attribute:"synopsis", value:"The remote mail server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Sendmail mail server
earlier than 8.13.2. Such versions are reportedly affected by a remote
buffer overflow vulnerability. An attacker could leverage this flaw to
execute arbitrary code with the privileges of the affected
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nmrc.org/~thegnome/blog/apr09/");
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.13.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.13.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencies("find_service1.nasl", "smtpserver_detect.nasl");
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
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

banner = get_smtp_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the SMTP server's banner on port "+port+".");
if (!ereg(pattern:"[Ss]endmail ",string:banner)) exit(0, "The STMP server's banner on port "+port+" is not from Sendmail.");

matches = eregmatch(pattern:"[Ss]endmail[^0-9/]*([0-9.]+)", string:banner);
if (!isnull(matches)) exit(1, "Failed to determine the version of Sendmail based on the banner from port "+port+".");

version = matches[1];
if (version =~ "^([0-7]\.[0-9\.]+|8\.([0-9]($|\.[0-9]+)|1[0-2]($|\.[0-9]+)|13($|\.[01])))$")
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus found the following affected version of Sendmail installed on the \n",
      "remote host :\n",
      "\n",
      "  ", version, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The version of Sendmail listening on port "+port+" is not affected since it is version "+version+".");
