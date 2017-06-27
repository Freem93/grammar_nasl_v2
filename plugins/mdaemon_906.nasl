#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22256);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/28 14:57:12 $");

  script_cve_id("CVE-2006-4364");
  script_bugtraq_id(19651);
  script_osvdb_id(28125);

  script_name(english:"MDaemon < 9.0.6 POP3 Server USER / APOP Command Remote Overflow");
  script_summary(english:"Checks version of MDaemon POP3 Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is affected by multiple buffer overflow
flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the POP3 server bundled with the version of
MDaemon on the remote host has two buffer overflows that can be
triggered with long arguments to the 'USER' and 'APOP' commands.  By
exploiting these issues, a remote, unauthenticated user can reportedly
crash the affected service or run arbitrary code with LOCAL SYSTEM
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.infigo.hr/en/in_focus/advisories/INFIGO-2006-08-04");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444015/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon version 9.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

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

fix = "9.0.6";
if (version =~ "^([0-8]\.|9\.0\.[0-5]($|[^0-9]))")
{
  if (report_verbosity > 0)
  {
    report =
    '\n' +
    '\n  Source            : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "MDaemon", port, version);
