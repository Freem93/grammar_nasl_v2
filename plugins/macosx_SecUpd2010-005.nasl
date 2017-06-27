#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(48424);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2010-0098",
    "CVE-2010-0397",
    "CVE-2010-1129",
    "CVE-2010-1205",
    "CVE-2010-1311",
    "CVE-2010-1800",
    "CVE-2010-1801",
    "CVE-2010-1802",
    "CVE-2010-1808",
    "CVE-2010-2063",
    "CVE-2010-2225",
    "CVE-2010-2484",
    "CVE-2010-2531"
  );
  script_bugtraq_id(
    38708, 
    39262, 
    40884, 
    40948, 
    41174, 
    42651, 
    42652, 
    42653, 
    42655
  );
  script_osvdb_id(
    62583,
    63078,
    63818,
    63861,
    65518,
    65755,
    65852,
    66804,
    66805,
    67639,
    67640,
    67641,
    67642
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2010-005)");
  script_summary(english:"Check for the presence of Security Update 2010-005");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes security
issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6 or 10.5 that
does not have Security Update 2010-005 applied. 

This security update contains fixes for the following products :

  - ATS
  - CFNetwork
  - ClamAV
  - CoreGraphics
  - libsecurity
  - PHP
  - Samba"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4312"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Aug/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2010-005 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba chain_reply Memory Corruption (Linux x86)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^(9\.[0-8]\.|10\.[0-4]\.)", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2010\.00[5-9]|201[1-9]\.[0-9]+)(\.snowleopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2010-005 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
