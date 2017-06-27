#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80195);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2010-0738",
    "CVE-2010-1428",
    "CVE-2010-1429",
    "CVE-2011-5245",
    "CVE-2012-0818",
    "CVE-2012-3143",
    "CVE-2013-1502",
    "CVE-2013-1511",
    "CVE-2013-1532",
    "CVE-2013-1537",
    "CVE-2013-1544",
    "CVE-2013-1557",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-2375",
    "CVE-2013-2376",
    "CVE-2013-2389",
    "CVE-2013-2391",
    "CVE-2013-2392",
    "CVE-2013-2422",
    "CVE-2013-3783",
    "CVE-2013-3793",
    "CVE-2013-3794",
    "CVE-2013-3801",
    "CVE-2013-3802",
    "CVE-2013-3804",
    "CVE-2013-3805",
    "CVE-2013-3808",
    "CVE-2013-3809",
    "CVE-2013-3812",
    "CVE-2013-3839",
    "CVE-2014-3413"
  );
  script_bugtraq_id(
    39710,
    51748,
    51766,
    56055,
    59170,
    59194,
    59201,
    59207,
    59209,
    59211,
    59224,
    59227,
    59228,
    59229,
    59239,
    59242,
    59826,
    61129,
    61210,
    61222,
    61227,
    61244,
    61249,
    61256,
    61260,
    61264,
    61269,
    61272,
    63109
  );
  script_osvdb_id(
    64171,
    64172,
    64173,
    78679,
    78680,
    86351,
    92343,
    92344,
    92366,
    92467,
    92470,
    92472,
    92473,
    92474,
    92477,
    92479,
    92483,
    92485,
    93366,
    95322,
    95323,
    95325,
    95327,
    95328,
    95330,
    95331,
    95332,
    95333,
    95336,
    95498,
    98508,
    106940
  );
  script_xref(name:"TRA", value:"TRA-2014-01");
  script_xref(name:"EDB-ID", value:"17924");
  script_xref(name:"EDB-ID", value:"16274");
  script_xref(name:"EDB-ID", value:"16319");
  script_xref(name:"EDB-ID", value:"16316");

  script_name(english:"Juniper Junos Space < 13.3R1.8 Multiple Vulnerabilities (JSA10627)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 13.3R1.8. It is, therefore, affected by multiple
vulnerabilities in bundled third party software components :

  - Multiple vulnerabilities in RedHat JBoss application
    server. (CVE-2010-0738, CVE-2010-1428, CVE-2010-1429,
    CVE-2011-5245, CVE-2012-0818)

  - Multiple vulnerabilities in Oracle Java SE JDK.
    (CVE-2012-3143, CVE-2013-1537, CVE-2013-1557,
    CVE-2013-2422)

  - Multiple vulnerabilities in Oracle MySQL server.
    (CVE-2013-1502, CVE-2013-1511, CVE-2013-1532,
    CVE-2013-1544, CVE-2013-2375, CVE-2013-2376,
    CVE-2013-2389, CVE-2013-2391, CVE-2013-2392,
    CVE-2013-3783, CVE-2013-3793, CVE-2013-3794,
    CVE-2013-3801, CVE-2013-3802, CVE-2013-3804,
    CVE-2013-3805, CVE-2013-3808, CVE-2013-3809,
    CVE-2013-3812, CVE-2013-3839)

  - Multiple vulnerabilities in Apache HTTP Server.
    (CVE-2013-1862, CVE-2013-1896)

  - Known hard-coded MySQL credentials. (CVE-2014-3413)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2014-01");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10627");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 13.3R1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-132");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JBoss JMX Console Deployer Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'13.3R1.8', severity:SECURITY_HOLE);
