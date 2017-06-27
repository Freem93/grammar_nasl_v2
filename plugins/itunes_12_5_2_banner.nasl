#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94934);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2016-4613", "CVE-2016-7578");
  script_bugtraq_id(93949);
  script_osvdb_id(146224, 146369);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-10-27-3");

  script_name(english:"Apple iTunes < 12.5.2 Multiple Vulnerabilities (Uncredentialed Check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes running on the remote Windows host is
prior to 12.5.2 It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists in WebKit
    when handling the location attribute due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    web content, to disclose sensitive information on the
    user's system. (CVE-2016-4613)

  - Multiple memory corruption issues exist in WebKit due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these, via
    specially crafted web content, to execute arbitrary
    code. (CVE-2016-7578)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207274");
  # https://lists.apple.com/archives/security-announce/2016/Oct/msg00007.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de74ff03");
  script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/id/1037139");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");

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

fixed_version = "12.5.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  report = '\n  Version source    : ' + source +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fixed_version + 
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
