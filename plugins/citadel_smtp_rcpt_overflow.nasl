#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30123);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2008-0394");
  script_bugtraq_id(27376);
  script_osvdb_id(40516);
  script_xref(name:"EDB-ID", value:"4949");

  script_name(english:"Citadel SMTP makeuserkey Function RCPT TO Command Remote Overflow");
  script_summary(english:"Checks Citadel's version number");

  script_set_attribute(attribute:"synopsis", value:"The remote mail server is prone to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The remote server is running Citadel, an open source solution for
email and collaboration.

According to its version, the installation of Citadel on the remote
host uses insufficient bounds-checking in its SMTP service during
memory-copy operations when processing input to the RCPT TO command.
An unauthenticated, remote attacker may be able to leverage this issue
to cause a stack-based buffer overflow, resulting in a crash of the
affected service or even execution of arbitrary code.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citadel version 7.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citadel:smtp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "smtpserver_detect.nasl", "citadel_overflow.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25, "Services/citadel/ux", 504);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);


citadel_port = get_kb_item("Services/citadel/ux");
if (!citadel_port) exit(0);

kb = get_kb_item("citadel/" + citadel_port + "/version");
if (!kb) exit(0);


port = get_kb_item("Services/smtp");
if (!port) port = 25;

banner = get_smtp_banner(port:port);
if (banner && "ESMTP Citadel server ready." >< banner)
{
  ver = ereg_replace(pattern:"^Citadel(/UX)? +([0-9]+.+)$", replace:"\2", string:kb);
  if (ver && ver =~ "^[0-6]\.|7\.0|10($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote Citadel server reports itself as :\n",
        "\n",
        "  ", kb, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
