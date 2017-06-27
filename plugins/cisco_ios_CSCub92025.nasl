#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66762);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2013-1241");
  script_bugtraq_id(59774);
  script_osvdb_id(93091);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub92025");

  script_name(english:"Cisco IOS ISM Module for ISR G2 Authentication Header DoS");
  script_summary(english:"Checks IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco ISM module for ISR G2 has a denial of service vulnerability.
According to its self-reported IOS version, the remote device may be
affected by this vulnerability.  A remote, authenticated attacker
could exploit this issue by sending malformed authentication header
packets over an established IPsec security association, causing a device
reload."
  );
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=29252");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-1241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1854d0b");
  script_set_attribute(
    attribute:"solution",
    value:"Contact Cisco for updated software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '15.3(1)T')
  security_warning(0);
else if (version == '15.3(1)T1')
  security_warning(0);
else if (version == '15.3(1)T2')
  security_warning(0);
else if (version == '15.3(1)T3')
  security_warning(0);
else if (version == '15.3(1)T4')
  security_warning(0);
else if (version == '15.3(100)T')
  security_warning(0);
else if (version == '15.3(2)T')
  security_warning(0);
else if (version == '15.3(2)T1')
  security_warning(0);
else if (version == '15.3(2)T2')
  security_warning(0);
else if (version == '15.3(200)T')
  security_warning(0);
else if (version == '15.3(3)T')
  security_warning(0);
else
  audit(AUDIT_INST_VER_NOT_VULN, 'IOS', version);
