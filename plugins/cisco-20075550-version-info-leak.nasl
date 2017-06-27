#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17777);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/11 19:30:34 $");

  script_cve_id("CVE-2007-5550");
  script_osvdb_id(45469);

  script_name(english:"Cisco IOS Common Network Service Remote Version Disclosure");
  script_summary(english:"Checks IOS version");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote device is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Cisco device is potentially affected by an unspecified
vulnerability involving a 'common network service' that may allow a
remote attacker to determine the IOS version."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"There is currently no known fix or patch to address this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");
  
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/PCI_DSS");

  exit(0);
}

include("cisco_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');

# Only PCI considers this an issue
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

security_warning(port:0, extra:version);
