#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17772);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2002-1768");
  script_bugtraq_id(4948);
  script_osvdb_id(59754);
  script_xref(name:"CISCO-BUG-ID", value:"CSCdt64533");

  script_name(english:"Cisco IOS Hot Standby Routing Protocol Crafted UDP Packets Denial of Service");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a security vulnerability.");
  script_set_attribute(attribute:"description", value:
"When Hot Standby Routing Protocol (HSRP) is not enabled, it is
possible to cause a denial of service via randomly sized UDP packets
to the HSRP port 1985.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/33");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/PCI_DSS");

  exit(0);
}

include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Only PCI considers this an issue
if (!get_kb_item("Settings/PCI_DSS")) exit(0, 'PCI-DSS compliance checking is not enabled.');

security_warning(port:0, extra:version);
