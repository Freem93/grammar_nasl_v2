#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66202);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/24 23:41:59 $");

  script_cve_id("CVE-2013-1217");
  script_bugtraq_id(59357);
  script_osvdb_id(92633);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub41105");

  script_name(english:"Cisco IOS Generic Input/Output SNMP DoS");
  script_summary(english:"Checks IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco IOS device has a denial of service vulnerability in
the generic input/output control mechanism that could allow an
authenticated, remote attacker to trigger a reload of the Supervisor
Engine or the device; thus resulting in a denial of service condition."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-1217
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8152fda");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=29048
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70b830f4");

  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the bug details
for CSCub41105."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '15.0(2)SQA')
  security_warning(0);
else if (version == '15.0(2)SQA1')
  security_warning(0);
else if (version == '15.0(2)SQA2')
  security_warning(0);
else
  audit(AUDIT_INST_VER_NOT_VULN, 'IOS', version);
