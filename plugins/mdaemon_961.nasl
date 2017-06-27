#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25683);
  script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2007-3622");
  script_bugtraq_id(24787);
  script_osvdb_id(37193);

  script_name(english:"MDaemon Server DomainPOP Malformed Message DoS");
  script_summary(english:"Checks version of MDaemon");

  script_set_attribute(attribute:"synopsis", value:"The remote mail server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of MDaemon installed on the remote
host contains a vulnerability in its 'DomainPOP' Mail Collection
component that may cause it to crash while processing a specially
crafted message.  An unauthenticated, remote attacker may be able to
leverage this issue to deny service to legitimate users of the
application.");
  script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 9.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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

fix = "9.6.1";
if (version =~ "^([0-8]\.|(9\.[0-5]|9\.6\.0)($|[^0-9]))")
{
  if (report_verbosity > 0)
  {
    report =
    '\n' +
    '\n  Source            : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
} 
else audit(AUDIT_LISTEN_NOT_VULN, "MDaemon", port, version);
