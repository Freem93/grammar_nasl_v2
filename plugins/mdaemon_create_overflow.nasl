#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11577);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2003-1470");
  script_bugtraq_id(7446);
  script_osvdb_id(55186);

  script_name(english:"MDaemon IMAP Server CREATE Command Mailbox Name Handling Overflow");
  script_summary(english:"Determines the version number of the remote IMAP server");

  script_set_attribute(attribute:"synopsis", value:"The remote IMAP server has a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description",  value:
"According to its banner, the version of MDaemon running on the remote
host has a buffer overflow vulnerability in the CREATE command.  A
remote attacker could exploit this to execute arbitrary code, or cause a
denial of service.  A crash would prevent other MDaemon services (SMTP,
POP) from running as well.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/353");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 6.7.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("mdaemon_detect.nasl");
  script_require_keys("mdaemon/installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("mdaemon/port");

version = get_kb_item_or_exit("mdaemon/"+port+"/version");
source = get_kb_item_or_exit("mdaemon/"+port+"/source");

fix = "6.7.10";
if (version =~ "^([0-5]\.|(6\.[0-6]|6\.7\.[0-9])($|[^0-9]))")
{
  if (report_verbosity > 0)
  {
    report =
    '\n' +
    '\n  Source            : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "MDaemon", port, version);
