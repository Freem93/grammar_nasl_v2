#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17716);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2006-1014");
  script_bugtraq_id(16878);
  script_osvdb_id(23534);

  script_name(english:"PHP mb_send_mail() Function Parameter Security Bypass");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by a
security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is affected by a flaw that allows an attacker to gain
unauthorized privileges.  When used with sendmail and when accepting
remote input for the additional_parameters argument to the
mb_send_mail function, it is possible for context-dependent attackers
to read and create arbitrary files."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426342/100/0/threaded");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "Settings/PCI_DSS");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

# Only PCI considers this an issue
if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

# nb: unfixed.
if (report_verbosity > 0)
{
  report =
    '\n  Version source     : '+source +
    '\n  Installed version  : '+version + 
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
