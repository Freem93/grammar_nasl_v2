#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20218);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/08/03 13:57:41 $");

  script_cve_id("CVE-2005-2938");
  script_bugtraq_id(15446);
  script_osvdb_id(20988);

  script_name(english:"Apple iTunes For Windows iTunesHelper.exe Path Subversion Local Privilege Escalation (uncredentialed check)");
  script_summary(english:"Checks for a local code execution vulnerability in iTunes for Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a local
code execution flaw.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple iTunes for Windows on
the remote host launches a helper application by searching for it
through various system paths. By placing a malicious program in a
system path, an attacker with local access can exploit this behavior
to execute code before the helper application and thereby gain
privileges.");
  # The tiny URL link below now goes to the following, but the verisigninc.com archive only
  # reaches back to the year 2008. So the link is dead and a replacement couldn't be found.
  # http://www.verisigninc.com/en_US/cyber-security/security-intelligence/vulnerability-reports/index.xhtml
  # script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d16d359");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2005/Nov/msg00001.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 6 for Windows or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

get_kb_item_or_exit("iTunes/" + port + "/enabled");

type = get_kb_item_or_exit("iTunes/" + port + "/type");
source = get_kb_item_or_exit("iTunes/" + port + "/source");
version = get_kb_item_or_exit("iTunes/" + port + "/version");

if (type != 'Windows') audit(AUDIT_OS_NOT, "Windows");

if (version =~ "^5\.")
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 6.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
