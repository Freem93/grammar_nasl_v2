#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73736);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2014-2143");
  script_bugtraq_id(66628);
  script_osvdb_id(105349);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun31021");

  script_name(english:"Cisco IOS IKE Module DoS");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Internet Key Exchange (IKE) module has a denial of service
vulnerability. According to its self-reported IOS version, the remote
device may be affected by this vulnerability. The IKE module does not
handle specially crafted main mode packets and can allow established
IKE security associations to be damaged.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-2143
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc5a5c78");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33639");
  script_set_attribute(attribute:"solution", value:"Contact Cisco for updated software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (
  version == '15.4T'      ||
  version == '15.4(1)T'   ||
  version == '15.4S'      ||
  version == '15.4(3)S'
) security_warning(0);
else audit(AUDIT_INST_VER_NOT_VULN, 'IOS', version);
