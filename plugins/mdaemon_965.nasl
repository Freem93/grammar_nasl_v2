#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31640);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2008-1358");
  script_bugtraq_id(28245);
  script_osvdb_id(43111);
  script_xref(name:"EDB-ID", value:"5248");
  script_xref(name:"Secunia", value:"29382");

  script_name(english:"MDaemon IMAP Server FETCH Command Remote Buffer Overflow");
  script_summary(english:"Checks version in MDaemon's banners");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of MDaemon installed on the remote
host contains a stack-based buffer overflow in its IMAP server component
that can be triggered via a FETCH command with a long BODY data item. 
An authenticated, remote attacker may be able to leverage this issue to
crash the affected service or execute arbitrary code subject to the
privileges under which the service operates. 

Note that MDaemon by default runs as a service with SYSTEM privileges
under Windows so successful exploitation could result in a complete
compromise of the affected system.");
  script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 9.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MDaemon 9.6.4 IMAPD FETCH Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

fix = "9.6.5";
if (version =~ "^([0-8]\.|(9\.[0-5]|9\.6\.[0-4])($|[^0-9]))")
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
