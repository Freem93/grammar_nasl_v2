#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35914);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2009-0016", "CVE-2009-0143");
  script_bugtraq_id(34094);
  script_osvdb_id(52578, 52579);

  script_name(english:"Apple iTunes < 8.1 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
8.1. It is, therefore, affected by multiple vulnerabilities :

  - A remote attacker can cause a denial of service by
    sending a maliciously crafted DAAP message. Note that
    this vulnerability only affects iTunes running on a
    Windows host. (CVE-2009-0016)

  - When subscribing to a podcast, an authentication dialog
    may be presented to the user without clarifying the
    origin of the authentication request. An attacker could
    exploit this flaw in order to steal the user's iTunes
    credentials. (CVE-2009-0143)");

  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3487");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Mar/msg00001.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

get_kb_item_or_exit("iTunes/" + port + "/enabled");

type = get_kb_item_or_exit("iTunes/" + port + "/type");
source = get_kb_item_or_exit("iTunes/" + port + "/source");
version = get_kb_item_or_exit("iTunes/" + port + "/version");

if (type == 'AppleTV') audit(AUDIT_LISTEN_NOT_VULN, "iTunes on AppleTV", port, version);

fixed_version = "8.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source     : ' + source +
             '\n  Installed version  : ' + version +
             '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
