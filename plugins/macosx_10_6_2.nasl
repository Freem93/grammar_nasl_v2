#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(42434);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2009-0023",
    "CVE-2009-1191",
    "CVE-2009-1195",
    "CVE-2009-1574",
    "CVE-2009-1632",
    "CVE-2009-1890",
    "CVE-2009-1891",
    "CVE-2009-1955",
    "CVE-2009-1956",
    "CVE-2009-2202",
    "CVE-2009-2203",
    "CVE-2009-2285",
    "CVE-2009-2408",
    "CVE-2009-2409",
    "CVE-2009-2411",
    "CVE-2009-2412",
    "CVE-2009-2414",
    "CVE-2009-2416",
    "CVE-2009-2666",
    "CVE-2009-2798",
    "CVE-2009-2799",
    "CVE-2009-2808",
    "CVE-2009-2810",
    "CVE-2009-2818",
    "CVE-2009-2820",
    "CVE-2009-2823",
    "CVE-2009-2825",
    "CVE-2009-2830",
    "CVE-2009-2832",
    "CVE-2009-2834",
    "CVE-2009-2835",
    "CVE-2009-2836",
    "CVE-2009-2837",
    "CVE-2009-2839",
    "CVE-2009-3235"
  );
  script_bugtraq_id(
    34663,
    35115,
    35221,
    35251,
    35451,
    35565,
    35623,
    35888,
    35983,
    36328,
    36377,
    36963,
    36964,
    36974,
    36975,
    36977,
    36979,
    36983,
    36984,
    36985,
    36987,
    36990
  );
  script_osvdb_id(
    53921,
    54286,
    54733,
    55057,
    55058,
    55059,
    55265,
    55553,
    55782,
    56400,
    56401,
    56752,
    56765,
    56766,
    56855,
    56856,
    56985,
    56990,
    57861,
    57862,
    57863,
    57864,
    58103,
    59854,
    59976,
    59977,
    59978,
    59979,
    59982,
    59989,
    59990,
    59991,
    59992,
    59994,
    59997,
    60000
  );

  script_name(english:"Mac OS X 10.6.x < 10.6.2 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6.x that is prior
to 10.6.2.

Mac OS X 10.6.2 contains security fixes for the following products :

  - Adaptive Firewall
  - Apache
  - Apache Portable Runtime
  - Certificate Assistant
  - CoreMedia
  - CUPS
  - Dovecot
  - fetchmail
  - file
  - FTP Server
  - Help Viewer
  - ImageIO
  - IOKit
  - IPSec
  - Kernel
  - Launch Services
  - libsecurity
  - libxml
  - Login Window
  - OpenLDAP
  - QuickDraw Manager
  - QuickTime
  - Screen Sharing
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
    value:"Upgrade to Mac OS X 10.6.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 119, 189, 264, 310, 362, 399);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/11/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/11/09"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/09"
  );
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item("Host/OS");
  c = get_kb_item("Host/OS/Confidence");
  if ( isnull(os) || c <= 70 ) exit(0);
}
if (!os) exit(1, "The 'Host/OS' KB item is missing.");


if (ereg(pattern:"Mac OS X 10\.6($|\.[01]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
