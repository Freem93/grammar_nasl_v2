#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(47024);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/04/25 13:23:28 $");

  script_cve_id(
    "CVE-2009-1578",
    "CVE-2009-1579",
    "CVE-2009-1580",
    "CVE-2009-1581",
    "CVE-2009-2964",
    "CVE-2009-4212",
    "CVE-2010-0186",
    "CVE-2010-0187",
    "CVE-2010-0302",
    "CVE-2010-0540",
    "CVE-2010-0541",
    "CVE-2010-0543",
    "CVE-2010-0545",
    "CVE-2010-0546",
    "CVE-2010-0734",
    "CVE-2010-1374",
    "CVE-2010-1375",
    "CVE-2010-1381",
    "CVE-2010-1382",
    "CVE-2010-1411",
    "CVE-2010-1748",
    "CVE-2010-1816",
    "CVE-2010-1821"
  );
  script_bugtraq_id(
    34916,
    36196,
    37749,
    38198,
    38200,
    38510,
    40887,
    40889,
    40892,
    40893,
    40894,
    40895,
    40896,
    40897,
    40898
  );
  script_osvdb_id(
    54504,
    54505,
    54506,
    54507,
    54508,
    57001,
    60204,
    61795,
    62217,
    62300,
    62370,
    65296,
    65555,
    65556,
    65557,
    65558,
    65559,
    65561,
    65562,
    65567,
    65568,
    65569,
    156002,
    156003
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2010-004)");
  script_summary(english:"Check for the presence of Security Update 2010-004");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes a security
issue."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.5 that does not
have Security Update 2010-004 applied. 

This security update contains fixes for the following components :

  - CUPS
  - DesktopServices
  - Flash Player plug-in
  - Folder Manager
  - iChat
  - ImageIO
  - Kerberos
  - Kernel
  - libcurl
  - Network Authorization
  - Ruby
  - SMB File Server
  - SquirrelMail
  - Wiki Server"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4188"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2010-004 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 94, 189, 287, 352, 399);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^9\.[0-8]\.", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2010\.00[4-9]|201[1-9]\.[0-9]+)(\.leopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2010-004 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
