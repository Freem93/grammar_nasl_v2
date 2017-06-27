#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61574);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/11 19:44:18 $");

  script_cve_id("CVE-2012-1350");
  script_bugtraq_id(54837);
  script_osvdb_id(84536);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc12426");

  script_name(english:"Cisco IOS Aironet Access Point DoS");
  script_summary(english:"Checks IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco IOS device may have a denial of service
vulnerability.  An input queue wedge can occur when IOS is running on 
an Aironet Access Point.  This results in clients being unable to be
authenticated, resulting in a denial of service."
  );
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtc12426
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77472fe5");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the bug
details for CSCtc12426."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if(version == '12.3(2)JA')
  security_warning(0);
else if(version == '12.3(2)JA1')
  security_warning(0);
else if(version == '12.3(2)JA2')
  security_warning(0);
else if(version == '12.3(2)JA3')
  security_warning(0);
else if(version == '12.3(2)JA4')
  security_warning(0);
else if(version == '12.3(2)JA5')
  security_warning(0);
else if(version == '12.3(2)JA6')
  security_warning(0);
else if(version == '12.3(4)JA')
  security_warning(0);
else if(version == '12.3(4)JA1')
  security_warning(0);
else if(version == '12.3(4)JA2')
  security_warning(0);
else if(version == '12.3(7)JA')
  security_warning(0);
else if(version == '12.3(7)JA1')
  security_warning(0);
else if(version == '12.3(7)JA2')
  security_warning(0);
else if(version == '12.3(7)JA3')
  security_warning(0);
else if(version == '12.3(7)JA4')
  security_warning(0);
else if(version == '12.3(7)JA5')
  security_warning(0);
else if(version == '12.3(8)JA')
  security_warning(0);
else if(version == '12.3(8)JA1')
  security_warning(0);
else if(version == '12.3(8)JA2')
  security_warning(0);
else if(version == '12.3(11)JA')
  security_warning(0);
else if(version == '12.3(11)JA1')
  security_warning(0);
else if(version == '12.3(11)JA2')
  security_warning(0);
else if(version == '12.3(11)JA3')
  security_warning(0);
else if(version == '12.3(11)JA4')
  security_warning(0);
else if(version == '12.3(2)JK')
  security_warning(0);
else if(version == '12.3(2)JK1')
  security_warning(0);
else if(version == '12.3(2)JK2')
  security_warning(0);
else if(version == '12.3(2)JK3')
  security_warning(0);
else if(version == '12.3(2l)JK')
  security_warning(0);
else if(version == '12.3(8)JK')
  security_warning(0);
else if(version == '12.3(8)JK1')
  security_warning(0);
else if(version == '12.3(2)JL')
  security_warning(0);
else if(version == '12.3(2)JL1')
  security_warning(0);
else if(version == '12.3(2)JL2')
  security_warning(0);
else if(version == '12.3(2)JL3')
  security_warning(0);
else if(version == '12.3(2)JL4')
  security_warning(0);
else if(version == '12.3(2l)JL')
  security_warning(0);
else if(version == '12.3(7)JX')
  security_warning(0);
else if(version == '12.3(7)JX1')
  security_warning(0);
else if(version == '12.3(7)JX2')
  security_warning(0);
else if(version == '12.3(7)JX3')
  security_warning(0);
else if(version == '12.3(7)JX4')
  security_warning(0);
else if(version == '12.3(7)JX5')
  security_warning(0);
else if(version == '12.3(7)JX6')
  security_warning(0);
else if(version == '12.3(7)JX7')
  security_warning(0);
else if(version == '12.3(7)JX8')
  security_warning(0);
else if(version == '12.3(7)JX9')
  security_warning(0);
else if(version == '12.3(7)JX10')
  security_warning(0);
else if(version == '12.3(7)JX11')
  security_warning(0);
else if(version == '12.3(7)JX12')
  security_warning(0);
else if(version == '12.3(11)JX')
  security_warning(0);
else if(version == '12.3(11)JX1')
  security_warning(0);
else if(version == '12.3(2)XT')
  security_warning(0);
else if(version == '12.3(2)XT1')
  security_warning(0);
else if(version == '12.3(2)XT2')
  security_warning(0);
else if(version == '12.3(2)XT3')
  security_warning(0);
else if(version == '12.3(8)JEA')
  security_warning(0);
else if(version == '12.3(8)JEA1')
  security_warning(0);
else if(version == '12.3(8)JEA2')
  security_warning(0);
else if(version == '12.3(8)JEA3')
  security_warning(0);
else if(version == '12.3(8)JEB')
  security_warning(0);
else if(version == '12.3(8)JEB1')
  security_warning(0);
else if(version == '12.3(8)JEC')
  security_warning(0);
else if(version == '12.3(8)JEC1')
  security_warning(0);
else if(version == '12.3(8)JEC2')
  security_warning(0);
else if(version == '12.3(8)JEC3')
  security_warning(0);
else if(version == '12.3(8)JED')
  security_warning(0);
else if(version == '12.3(8)JEE')
  security_warning(0);
else
  audit(AUDIT_HOST_NOT, "affected");
