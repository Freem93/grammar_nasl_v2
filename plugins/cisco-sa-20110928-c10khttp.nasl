#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-c10k.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56313);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/07/09 00:38:38 $");

  script_cve_id("CVE-2011-3270");
  script_osvdb_id(76010);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtk62453");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-c10k");

  script_name(english:"Cisco 10000 Series Denial of Service Vulnerability (cisco-sa-20110928-c10k)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Cisco 10000 Series Router is affected by a denial of service (DoS)
vulnerability where an attacker could cause a device reload by sending
a series of ICMP packets. Cisco has released free software updates
that address this vulnerability. Workarounds that mitigate this
vulnerability are also available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-c10k
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?220f3dab"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-c10k."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.2(31)SB18' ) flag++;
if ( version == '12.2(31)SB19' ) flag++;
if ( version == '12.2(33)SB9' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;

if (flag)
{
  security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
