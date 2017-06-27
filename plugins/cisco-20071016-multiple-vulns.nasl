#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17776);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2007-5547", "CVE-2007-5548");
  script_osvdb_id(45360, 45361, 43742);

  script_name(english:"Cisco IOS Multiple Vulnerabilities");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is potentially affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability can be exploited
    via unspecified vectors. (CVE-2007-5547)

  - Multiple stack-based buffer overflows in Command EXEC
    allow local users to gain privileges via unspecified
    vectors. (CVE-2007-5548)");
  script_set_attribute(attribute:"solution", value:
"There are currently no known fixes or patches to address these
issues.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/10");
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

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

set_kb_item(name:'www/0/XSS', value:TRUE);
security_warning(port:0, extra:version);
