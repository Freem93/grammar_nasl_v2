#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53489);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/08/03 13:57:40 $");

  script_cve_id("CVE-2011-1290", "CVE-2011-1344");
  script_bugtraq_id(46849, 46822);
  script_osvdb_id(71182, 72690);

  script_name(english:"Apple iTunes < 10.2.2 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
10.2.2. It is, therefore, affected by multiple vulnerabilities in the
WebKit component :

  - An integer overflow vulnerability exists in the handling
    of nodesets that can be exploited by a remote attacker
    to execute arbitrary code. (CVE-2011-1290)

  - A use-after-free vulnerability exists in the handling of
    text nodes that can be exploited by a remote attacker to
    execute arbitrary code. (CVE-2011-1344)

Note that these only affect WebKit for Windows.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4609");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Apr/msg00004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

fixed_version = "10.2.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
