#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(38743);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186", "CVE-2006-0747", "CVE-2007-2754",
                "CVE-2008-2939", "CVE-2008-3529", "CVE-2008-3651", "CVE-2008-3652", "CVE-2008-3790",
                "CVE-2008-3863", "CVE-2008-4309", "CVE-2008-5077", "CVE-2009-0010", "CVE-2009-0021",
                "CVE-2009-0025", "CVE-2009-0114", "CVE-2009-0145", "CVE-2009-0146", "CVE-2009-0147",
                "CVE-2009-0148", "CVE-2009-0149", "CVE-2009-0154", "CVE-2009-0156", "CVE-2009-0158",
                "CVE-2009-0159", "CVE-2009-0160", "CVE-2009-0164", "CVE-2009-0165", "CVE-2009-0519",
                "CVE-2009-0520", "CVE-2009-0846", "CVE-2009-0847", "CVE-2009-0942", "CVE-2009-0943",
                "CVE-2009-0944", "CVE-2009-0946");
  script_bugtraq_id(30087, 30657, 33890, 34408, 34409, 34481, 34550, 34568, 34665, 34805,
                    34932, 34937, 34938, 34939, 34941, 34942, 34947, 34948, 34950, 34952, 34962);
  script_osvdb_id(
    13154,
    13155,
    13156,
    26032,
    36509,
    47374,
    47460,
    47474,
    47753,
    48158,
    49224,
    49524,
    51164,
    51368,
    52747,
    52748,
    52749,
    53383,
    53385,
    53593,
    54068,
    54069,
    54070,
    54438,
    54440,
    54441,
    54443,
    54444,
    54445,
    54446,
    54450,
    54451,
    54452,
    54461,
    54495,
    54496,
    54497,
    56273,
    56274
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2009-002)");
  script_summary(english:"Check for the presence of Security Update 2009-002");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote host is missing a Mac OS X update that fixes various
security issues."  );
  script_set_attribute(  attribute:"description",   value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2009-002 applied.

This security update contains fixes for the following products :

  - Apache
  - ATS
  - BIND
  - CoreGraphics
  - Cscope
  - CUPS
  - Disk Images
  - enscript
  - Flash Player plug-in
  - Help Viewer
  - IPSec
  - Kerberos
  - Launch Services
  - libxml
  - Net-SNMP
  - Network Time
  - OpenSSL
  - QuickDraw Manager
  - Spotlight
  - system_cmds
  - telnet
  - Terminal
  - X11"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3549"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/May/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2009-002 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 94, 119, 189, 200, 287, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/21");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/05/12");
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

#

uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(0);

  if (!egrep(pattern:"^SecUpd(Srvr)?(2009-00[2-5]|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
