#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91348);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/31 17:32:20 $");

  script_cve_id("CVE-2016-1742");
  script_osvdb_id(138643);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-05-16-6");

  script_name(english:"Apple iTunes < 12.4 DLL Injection Arbitrary Code Execution (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a DLL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes running on the remote Windows host is
prior to 12.4. It is, therefore, affected by a DLL (Dynamic Link
Library) injection vulnerability in the setup component that is
triggered when running the installer from an untrusted directory. An
attacker can exploit this vulnerability by placing a specially crafted
DLL file in the untrusted directory, resulting in the execution of
arbitrary code in the context of the current user.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206379");
  # https://lists.apple.com/archives/security-announce/2016/May/msg00006.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c25c376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

fixed_version = "12.4";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  report = '\n  Version source    : ' + source +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fixed_version + 
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
