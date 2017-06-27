#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(42433);
  script_version("$Revision: 1.24 $");

  script_cve_id(
    "CVE-2007-5707",
    "CVE-2007-6698",
    "CVE-2008-0658",
    "CVE-2008-5161",
    "CVE-2009-0023",
    "CVE-2009-1191",
    "CVE-2009-1195",
    "CVE-2009-1574",
    "CVE-2009-1632",
    "CVE-2009-1890",
    "CVE-2009-1891",
    "CVE-2009-1955",
    "CVE-2009-1956",
    "CVE-2009-2408",
    "CVE-2009-2409",
    "CVE-2009-2411",
    "CVE-2009-2412",
    "CVE-2009-2414",
    "CVE-2009-2416",
    "CVE-2009-2666",
    "CVE-2009-2808",
    "CVE-2009-2818",
    "CVE-2009-2819",
    "CVE-2009-2820",
    "CVE-2009-2823",
    "CVE-2009-2824",
    "CVE-2009-2825",
    "CVE-2009-2826",
    "CVE-2009-2827",
    "CVE-2009-2828",
    "CVE-2009-2829",
    "CVE-2009-2831",
    "CVE-2009-2832",
    "CVE-2009-2833",
    "CVE-2009-2834",
    "CVE-2009-2837",
    "CVE-2009-2838",
    "CVE-2009-2839",
    "CVE-2009-2840",
    "CVE-2009-3111",
    "CVE-2009-3291",
    "CVE-2009-3292",
    "CVE-2009-3293"
  );
  script_bugtraq_id(
    26245,
    27778,
    34663,
    35115,
    35221,
    35251,
    35565,
    35623,
    35888,
    35983,
    36263,
    36449,
    36959,
    36961,
    36962,
    36963,
    36964,
    36966,
    36967,
    36972,
    36973,
    36975,
    36977,
    36978,
    36979,
    36982,
    36985,
    36988,
    36990
  );
  script_osvdb_id(
    38484,
    41948,
    43306,
    50036,
    53921,
    54286,
    54733,
    55057,
    55058,
    55059,
    55553,
    55782,
    56400,
    56401,
    56723,
    56752,
    56765,
    56766,
    56855,
    56856,
    56985,
    56990,
    57897,
    58185,
    58186,
    58187,
    59854,
    59976,
    59978,
    59979,
    59980,
    59981,
    59982,
    59984,
    59985,
    59986,
    59987,
    59988,
    59990,
    59991,
    59993,
    59994,
    59996,
    59997,
    59998
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2009-006)");
  script_summary(english:"Check for the presence of Security Update 2009-006");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.5 that does not
have Security Update 2009-006 applied.

This security update contains fixes for the following products :

  - AFP Client
  - Adaptive Firewall
  - Apache
  - Apache Portable Runtime
  - ATS
  - Certificate Assistant
  - CoreGraphics
  - CUPS
  - Dictionary
  - DirectoryService
  - Disk Images
  - Event Monitor
  - fetchmail
  - FTP Server
  - Help Viewer
  - International Components for Unicode
  - IOKit
  - IPSec
  - libsecurity
  - libxml
  - OpenLDAP
  - OpenSSH
  - PHP
  - QuickDraw Manager
  - QuickLook
  - FreeRADIUS
  - Screen Sharing
  - Spotlight
  - Subversion"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3937"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Nov/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/18255"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2009-006 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 119, 189, 200, 255, 264, 310, 399);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/09");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");

darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^(9\.[0-8]\.)", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2009\.00[6-9]|20[1-9][0-9]\.[0-9]+)\.bom", string:packages))
    exit(0, "The host has Security Update 2009-006 or later installed and therefore is not affected.");
  else
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
