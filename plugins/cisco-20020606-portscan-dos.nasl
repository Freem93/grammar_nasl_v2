#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17774);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2002-2052");
  script_bugtraq_id(4947);
  script_osvdb_id(60030);

  script_name(english:"Cisco IOS Portscan Remote Denial of Service");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"It is possible to cause a denial of service by scanning all ports on
the host or scanning a network of hosts for a single open port through
the device.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IOS 12.1(6a), as it is reportedly unaffected by the
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
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

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');

# Cisco wasn't able to reproduce this issue, so only run the check if 
# PCI_DSS is enabled
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Affected 12.1
if (check_release(version:version, patched:make_list('12.1(6a)')))
{
  security_warning(port:0, extra:'\nUpdate to '+patch_update+' or later.\n');
  exit(0);
}

exit(0, "The host is not affected.");
