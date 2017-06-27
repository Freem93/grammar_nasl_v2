#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2013-5544. The text itself is
# copyright (C) Cisco.
#

include("compat.inc");

if (description)
{
  script_id(72485);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/13 18:33:23 $");

  script_cve_id("CVE-2013-5544");
  script_bugtraq_id(63262);
  script_osvdb_id(98817);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua91108");

  script_name(english:"Cisco ASA VPN Denial of Service (CSCua91108)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the VPN authentication code that handles parsing of
the username from the certificate on the Cisco ASA firewall could allow
an unauthenticated, remote attacker to cause a reload of the affected
device. 

The vulnerability is due to parallel processing of a large number of
Internet Key Exchange (IKE) requests for which username-from-cert is
configured.  An attacker could exploit this vulnerability by sending a
large number of IKE requests when the affected device is configured with
the username-from-cert command.  An exploit could allow the attacker to
cause a reload of the affected device, leading to a denial of service
(DoS) condition."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5544
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b6bddb6");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCua91108.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9]') audit(AUDIT_HOST_NOT, 'ASA 5500');


if (
  cisco_gen_ver_compare(a:version, b:"8.4(1)") == 0 ||
  cisco_gen_ver_compare(a:version, b:"8.4(1.3)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(1.11)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(2)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(2.1)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(2.8)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(3)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(3.8)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(3.9)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(4)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(4.1)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(4.3)") == 0  ||
  cisco_gen_ver_compare(a:version, b:"8.4(4.5)") == 0
)
{ 
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.4(4.6)' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_HOST_NOT, "affected");
