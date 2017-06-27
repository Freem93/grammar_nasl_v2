#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2013-5497. The text itself is
# copyright (C) Cisco.
#

include("compat.inc");

if (description)
{
  script_id(72510);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/14 16:56:40 $");

  script_cve_id("CVE-2013-5497");
  script_bugtraq_id(62517);
  script_osvdb_id(97525);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf20148");

  script_name(english:"Cisco IPS Authentication Manager Denial of Service Vulnerability (CSCuf20148)");
  script_summary(english:"Checks the IPS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the web framework of Cisco IPS Software could allow
an unauthenticated, remote attacker to cause MainApp to hang
intermittently due to the authentication manager process creating a
denial of service (DoS) condition. 

The vulnerability is due to improper handling of user tokens.  An
attacker could exploit this vulnerability by sending a crafted
connection request to the Cisco IPS management interface."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5497
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f07974dc");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCuf20148.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:intrusion_prevention_system");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IPS/Version');

fix = "";

if (version == "7.0(8)E4") { fix = "Upgrade to 7.0(9)E4 or later."; }

if (
  version == "7.1(4)E4" ||
  version == "7.1(5)E4" ||
  version == "7.1(6)E4" ||
  version == "7.1(7)E4") { fix = "Upgrade to 7.1(8)E4 or later."; }

if (!fix) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
