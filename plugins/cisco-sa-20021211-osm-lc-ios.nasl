#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17779);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/11 19:30:34 $");

  script_cve_id("CVE-2002-2239");
  script_bugtraq_id(6358);
  script_osvdb_id(60095);
  script_xref(name:"CISCO-BUG-ID", value:"CSCdy29717");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20021211-osm-lc-ios");

  script_name(english:"Cisco IOS OSM Line Card Header Corruption");
  script_summary(english:"Checks the version of Cisco IOS");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"The Optical Service Module (OSM) Line Cards installed in Catalyst
6500 or Cisco 7600 chassis are vulnerable a denial of service
attack upon receiving a specifically constructed or corrupted packet
from the local network.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c43f9b9");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20021211-osm-lc-ios.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");
  
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

include("cisco_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');

# Affected: 12.1E
if (check_release(version:version,
                  patched:make_list('12.1(13.5)E', '12.1(13)E1', '12.1(12c)E2')))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n');
  exit(0);
}

exit(0, "The host is not affected.");
