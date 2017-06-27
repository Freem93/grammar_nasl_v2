#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21783);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/08/03 13:57:40 $");

  script_cve_id("CVE-2006-1467");
  script_bugtraq_id(18730);
  script_osvdb_id(26909);

  script_name(english:"Apple iTunes AAC File Parsing Integer Overflow (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes running on the remote host is affected by
an integer overflow vulnerability when it parses specially crafted AAC
files. By convincing a user to open such a file, a remote attacker can
execute arbitrary code with the same level of privileges as the user.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10781");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/Jun/msg00001.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 6.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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

if (type == 'AppleTV') audit(AUDIT_LISTEN_NOT_VULN, "iTunes on AppleTV", port, version);

fixed_version = "6.0.5";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
