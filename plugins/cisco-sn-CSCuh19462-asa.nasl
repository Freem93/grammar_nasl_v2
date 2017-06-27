#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2013-3458. The text itself is
# copyright (C) Cisco.
#

include("compat.inc");

if (description)
{
  script_id(72509);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2013-3458");
  script_bugtraq_id(62251);
  script_osvdb_id(97038);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh19462");

  script_name(english:"Cisco ASA Certificate Processing Denial of Service (CSCuh19462)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"Cisco Adaptive Security Appliance (ASA) Software versions for symmetric
multi-processor (SMP) platforms contain a vulnerability that could allow
an unauthenticated, remote attacker to trigger the device to crash. 

The vulnerability is due to the SSL/TLS certificate handling code.  An
attacker could exploit this vulnerability by generating a heavy SSL/TLS
traffic load, which under selected circumstances may trigger the crash."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-3458
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1366ebae");

  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCuh19462.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Host/Cisco/ASA/SMP");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
smp = get_kb_item_or_exit('Host/Cisco/ASA/SMP');
version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if ((!model =~ '^55[0-9][0-9](|-)X') || (!smp)) audit(AUDIT_HOST_NOT, 'ASA 5500-X');


if (
  cisco_gen_ver_compare(a:version, b:"9.0(1)") == 0 ||
  cisco_gen_ver_compare(a:version, b:"9.0(2)") == 0 ||
  cisco_gen_ver_compare(a:version, b:"9.1(1)") == 0 ||
  cisco_gen_ver_compare(a:version, b:"9.1(1.4)") == 0 ||
  cisco_gen_ver_compare(a:version, b:"9.1(2)") == 0
)
{ 
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.1(2.99)' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
