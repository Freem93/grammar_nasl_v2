#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2013-5519. The text itself is copyright
# (C) Cisco.
#

include("compat.inc");

if (description)
{
  script_id(72460);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/24 19:17:53 $");

  script_cve_id("CVE-2013-5519");
  script_bugtraq_id(62787);
  script_osvdb_id(98083);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf77810");

  script_name(english:"Cisco WLC Web-Based Management Interface XSS Vulnerability (CSCuf77810)");
  script_summary(english:"Checks the WLC version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");

  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the web-based management interface of the Cisco
Wireless LAN Controller (WLC) could allow an unauthenticated, remote
attacker to conduct a cross-site scripting (XSS) attack against a user
of the web interface of the affected system. 

The vulnerability is due to insufficient input validation of a
user-supplied value.  An attacker could exploit this vulnerability by
convincing a user to click a crafted URL."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5519
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68ed3d05");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCuf77810.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
fix = "";

if (
  version == "3.0" ||
  version == "3.1.59.24" ||
  version == "3.1.105.0" ||
  version == "3.1.111.0" ||
  version == "3.2.78.0" ||
  version == "3.2.116.21" ||
  version == "3.2.150.6" ||
  version == "3.2.150.10" ||
  version == "3.2.171.5" ||
  version == "3.2.171.6" ||
  version == "3.2.185.0" ||
  version == "3.2.193.5" ||
  version == "3.2.195.10" ||
  version == "4.0.108" ||
  version == "4.0.155.0" ||
  version == "4.0.155.5" ||
  version == "4.0.179.8" ||
  version == "4.0.179.11" ||
  version == "4.0.196" ||
  version == "4.0.206.0" ||
  version == "4.0.217.0" ||
  version == "4.0.219.0" ||
  version == "4.1" ||
  version == "4.1.171.0" ||
  version == "4.1.181.0" ||
  version == "4.1.185.0" ||
  version == "4.2" ||
  version == "4.2.61.0" ||
  version == "4.2.99.0" ||
  version == "4.2.112.0" ||
  version == "4.2.117.0" ||
  version == "4.2.130.0" ||
  version == "4.2.173.0" ||
  version == "4.2.174.0" ||
  version == "4.2.176.0" ||
  version == "4.2.182.0" ||
  version == "5.0.148.0" ||
  version == "5.0.148.2" ||
  version == "5.1.151.0" ||
  version == "5.1.152.0" ||
  version == "5.1.160.0" ||
  version == "5.2.157.0" ||
  version == "5.2.169.0" ||
  version == "6.0" ||
  version == "6.0.182.0" ||
  version == "6.0.188.0" ||
  version == "6.0.196.0" ||
  version == "6.0.199.4" ||
  version == "6.0.202.0") { fix = "Upgrade to 7.0(241.5) or later."; }

  if (
  version == "7.0" ||
  version == "7.0.98.0" ||
  version == "7.0.98.218" ||
  version == "7.0.116.0" ||
  version == "7.0.220.0") { fix = "Upgrade to 7.0(241.5) or later."; }

if (
  version == "7.1" ||
  version == "7.1.91.0") { fix = "Upgrade to 7.4(110.17) or later."; }

if (
  version == "7.2" ||
  version == "7.2.103.0") { fix = "Upgrade to 7.4(110.17) or later."; }

if (
  version == "7.3" ||
  version == "7.3.101.0" ||
  version == "7.3.112") { fix = "Upgrade to 7.4(110.17) or later."; }

if (
  version == "7.4" ||
  version == "7.4.1.54" ||
  version == "7.4.100" ||
  version == "7.4.100.60" ||
  version == "7.4.110") { fix = "Upgrade to 7.4(110.17) or later."; }

if (
  version == "7.5" ||
  version == "7.5.102.0") { fix = "Upgrade to 7.6(100.0) or later."; }

if (!fix) audit(AUDIT_HOST_NOT, "affected");

set_kb_item(name: 'www/0/XSS', value: TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
