#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100465);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/26 23:51:37 $");

  script_osvdb_id(155255);

  script_name(english:"Postfix 2.x Mail Message Date Field RCE (ENTERSEED)");
  script_summary(english:"Checks version of Postfix SMTP banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the Postfix mail server running on the
remote host is version 2.x from 2.0.8 to 2.1.5 inclusively. It is,
therefore, affected by a remote code execution vulnerability due to
improper sanitization of the email date field. An unauthenticated,
remote attacker can exploit this, via a specially crafted email, to
execute arbitrary code.

ENTERSEED is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/04/08 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/x0rz/EQGRP/blob/master/Linux/bin/enterseed.py");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Postfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postfix:postfix");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_require_keys("Settings/ParanoidReport", "SMTP/postfix");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

app = "Postfix";
port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get the service's banner.
banner = chomp(get_smtp_banner(port:port));

# Ensure service is Postfix
if (empty_or_null(banner)) audit(AUDIT_NO_BANNER, port);
if (app >!< banner) audit(AUDIT_NOT_DETECT, app, port);

# Ensure Postfix provides version
if (banner !~ "^220.*Postfix.*[0-9]+\..*")
  audit(AUDIT_SERVICE_VER_FAIL, app, port);

# Match Postfix version loosely 
# e.g. 220 Postfix (2.0.8)
#      220 Postfix 2.1.5
pattern = "^220.*Postfix.*(2\.(?:0\.(?:[8-9]|(?:[0-9]{2,}))|(?:1\.[0-5]))).*";
match = pregmatch(pattern:pattern, string:banner);
if (!isnull(match))
{
  version = match[1];

  report =
    '\n  Banner            : ' + banner +
    '\n  Installed version : ' + version +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port);
