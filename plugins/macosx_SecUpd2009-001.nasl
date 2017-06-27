#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(35684);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id("CVE-2006-1861", "CVE-2006-3467", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667",
                "CVE-2007-4565", "CVE-2007-4965", "CVE-2008-1377", "CVE-2008-1379", "CVE-2008-1679",
                "CVE-2008-1721", "CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2008-1887",
                "CVE-2008-1927", "CVE-2008-2315", "CVE-2008-2316", "CVE-2008-2360", "CVE-2008-2361",
                "CVE-2008-2362", "CVE-2008-2379", "CVE-2008-2711", "CVE-2008-3142", "CVE-2008-3144",
                "CVE-2008-3663", "CVE-2008-4864", "CVE-2008-5031", "CVE-2008-5050", "CVE-2008-5183",
                "CVE-2008-5314", "CVE-2009-0009", "CVE-2009-0011", "CVE-2009-0012", "CVE-2009-0013",
                "CVE-2009-0014", "CVE-2009-0015", "CVE-2009-0017", "CVE-2009-0018", "CVE-2009-0019",
                "CVE-2009-0020", "CVE-2009-0137", "CVE-2009-0138", "CVE-2009-0139", "CVE-2009-0140",
                "CVE-2009-0141", "CVE-2009-0142");
  script_bugtraq_id(25495, 25696, 28715, 28749, 28928, 29705, 30491, 31976, 32207, 32555,
                    33187, 33796, 33798, 33800, 33806, 33808, 33809, 33810, 33811, 33812,
                    33813, 33814, 33815, 33816, 33820, 33821);
  script_osvdb_id(
    25654,
    27255,
    34107,
    34108,
    34109,
    34169,
    34170,
    34917,
    34918,
    40142,
    41724,
    41725,
    41726,
    44463,
    44588,
    44693,
    44730,
    45833,
    46175,
    46176,
    46177,
    46178,
    46187,
    46188,
    46189,
    46190,
    46191,
    46304,
    47478,
    47479,
    47480,
    47481,
    49095,
    49832,
    50097,
    50351,
    50363,
    50460,
    51964,
    51965,
    51966,
    51967,
    51968,
    51969,
    51970,
    51971,
    51972,
    51973,
    51974,
    51975,
    51977,
    51979,
    51980,
    53991
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2009-001)");
  script_summary(english:"Check for the presence of Security Update 2009-001");

  script_set_attribute(  attribute:"synopsis",   value:
"The remote host is missing a Mac OS X update that fixes various
security issues."  );
  script_set_attribute( attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that
does not have Security Update 2009-001 applied.

This security update contains fixes for the following products :

  - AFP Server
  - Apple Pixlet Video
  - CarbonCore
  - CFNetwork
  - Certificate Assistant
  - ClamAV
  - CoreText
  - CUPS
  - DS Tools
  - fetchmail
  - Folder Manager
  - FSEvents
  - Network Time
  - perl
  - Printing
  - python
  - Remote Apple Events
  - Safari RSS
  - servermgrd
  - SMB
  - SquirrelMail
  - X11
  - XTerm"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/ht3438"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Feb/msg00000.html"
  );
  script_set_attribute( attribute:"solution", value:
    "Install Security Update 2009-001 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 79, 119, 189, 255, 264, 287, 310, 362, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/13");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/02/12");
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

#

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

  if (egrep(pattern:"^SecUpd(Srvr)?(2009-00[1-9]|20[1-9][0-9]-)", string:packages))
    exit(0, "The host has Security Update 2009-001 or later installed and therefore is not affected.");
  else
    security_hole(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-6]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2009\.00[1-9]|20[1-9][0-9]\.[0-9]+)\.bom", string:packages))
    exit(0, "The host has Security Update 2009-001 or later installed and therefore is not affected.");
  else
    security_hole(0);
}
else exit(0, "The host is not affected.");
