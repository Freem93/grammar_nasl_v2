#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63644);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2012-5419");
  script_bugtraq_id(57432);
  script_osvdb_id(89311);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc42812");
  script_xref(name:"IAVA", value:"2013-A-0023");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc88741");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130116-asa1000v");

  script_name(english:"Cisco ASA 1000V H.323 Inspection DoS");
  script_summary(english:"Checks ASA model and version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported model and version number, the remote
Cisco ASA 1000V may be affected by a denial of service vulnerability. 
When H.323 inspection is enabled, processing malformed H.323 transit
traffic can result in a device reload.  A remote, unauthenticated
attacker could exploit this to cause a denial of service."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130116-asa1000v
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b13b16c5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco ASA Software 8.7(1)3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_1000v_cloud_firewall");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) exit(1, 'Unable to parse ASA version.');

if (model != '1000V')
  audit(AUDIT_HOST_NOT, 'ASA 1000V');

# "Versions 8.7.1 and 8.7.1.1 of Cisco ASA Software for the Cisco ASA 1000V Cloud
# Firewall are affected by this vulnerability if H.323 inspection is enabled."
if (ver != '8.7(1)' && ver != '8.7(1)1')
  audit(AUDIT_INST_VER_NOT_VULN, 'ASA 1000V', ver);

if (report_verbosity > 0)
{
  fix = '8.7(1)3';
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
