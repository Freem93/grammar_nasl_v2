#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(38744);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186", "CVE-2008-0456", "CVE-2008-1382",
                "CVE-2008-1517", "CVE-2008-2371", "CVE-2008-2383", "CVE-2008-2665", "CVE-2008-2666",
                "CVE-2008-2829", "CVE-2008-2939", "CVE-2008-3443", "CVE-2008-3529", "CVE-2008-3530",
                "CVE-2008-3651", "CVE-2008-3652", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657",
                "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2008-3790", "CVE-2008-3863",
                "CVE-2008-4309", "CVE-2008-5077", "CVE-2008-5557", "CVE-2009-0010", "CVE-2009-0021",
                "CVE-2009-0025", "CVE-2009-0040", "CVE-2009-0114", "CVE-2009-0144", "CVE-2009-0145",
                "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0148", "CVE-2009-0149", "CVE-2009-0150",
                "CVE-2009-0152", "CVE-2009-0153", "CVE-2009-0154", "CVE-2009-0155", "CVE-2009-0156",
                "CVE-2009-0157", "CVE-2009-0158", "CVE-2009-0159", "CVE-2009-0160", "CVE-2009-0161",
                "CVE-2009-0162", "CVE-2009-0164", "CVE-2009-0165", "CVE-2009-0519", "CVE-2009-0520",
                "CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847", "CVE-2009-0942",
                "CVE-2009-0943", "CVE-2009-0944", "CVE-2009-0945", "CVE-2009-0946", "CVE-2009-1717");
  script_bugtraq_id(27409, 29796, 30087, 30649, 30657, 31612, 32948, 33769, 33890, 34257, 34408,
                    34409, 34481, 34550, 34568, 34665, 34805, 34924, 34932, 34937, 34938, 34939,
                    34941, 34942, 34947, 34948, 34950, 34951, 34952, 34958, 34959, 34962, 34965,
                    34972, 34973, 34974, 35182);
  script_osvdb_id(
    13154,
    13155,
    13156,
    41018,
    44364,
    46584,
    46638,
    46639,
    46641,
    46690,
    47374,
    47460,
    47470,
    47471,
    47472,
    47474,
    47753,
    47796,
    47797,
    47798,
    47800,
    47919,
    48158,
    49224,
    49524,
    51142,
    51164,
    51368,
    51477,
    52194,
    52493,
    52747,
    52748,
    52749,
    52963,
    53315,
    53316,
    53317,
    53383,
    53384,
    53385,
    53593,
    54068,
    54069,
    54070,
    54437,
    54438,
    54439,
    54440,
    54441,
    54442,
    54443,
    54444,
    54445,
    54446,
    54447,
    54448,
    54449,
    54450,
    54451,
    54452,
    54453,
    54454,
    54455,
    54461,
    54497,
    54920,
    56273,
    56274,
    56505
  );

  script_name(english:"Mac OS X 10.5.x < 10.5.7 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues."  );
  script_set_attribute( attribute:"description",  value:
"The remote host is running a version of Mac OS X 10.5.x that is prior
to 10.5.7. 

Mac OS X 10.5.7 contains security fixes for the following products :

  - Apache
  - ATS
  - BIND
  - CFNetwork
  - CoreGraphics
  - Cscope
  - CUPS
  - Disk Images
  - enscript
  - Flash Player plug-in
  - Help Viewer
  - iChat
  - International Components for Unicode
  - IPSec
  - Kerberos
  - Kernel
  - Launch Services
  - libxml
  - Net-SNMP
  - Network Time
  - Networking
  - OpenSSL
  - PHP
  - QuickDraw Manager
  - ruby
  - Safari
  - Spotlight
  - system_cmds
  - telnet
  - Terminal
  - WebKit
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
    value:"Upgrade to Mac OS X 10.5.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 22, 79, 94, 119, 189, 200, 264, 287, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/21");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/05/12");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(0);

if (ereg(pattern:"Mac OS X 10\.5\.[0-6]([^0-9]|$)", string:os)) 
  security_hole(0);
