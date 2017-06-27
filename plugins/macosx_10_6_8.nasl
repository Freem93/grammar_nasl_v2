#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55416);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2009-3245",
    "CVE-2010-0740",
    "CVE-2010-2632",
    "CVE-2010-3677",
    "CVE-2010-3682",
    "CVE-2010-3790",
    "CVE-2010-3833",
    "CVE-2010-3834",
    "CVE-2010-3835",
    "CVE-2010-3836",
    "CVE-2010-3837",
    "CVE-2010-3838",
    "CVE-2010-3864",
    "CVE-2010-4180",
    "CVE-2010-4651",
    "CVE-2011-0014",
    "CVE-2011-0195",
    "CVE-2011-0197",
    "CVE-2011-0198",
    "CVE-2011-0199",
    "CVE-2011-0201",
    "CVE-2011-0202",
    "CVE-2011-0203",
    "CVE-2011-0204",
    "CVE-2011-0205",
    "CVE-2011-0206",
    "CVE-2011-0207",
    "CVE-2011-0208",
    "CVE-2011-0209",
    "CVE-2011-0210",
    "CVE-2011-0211",
    "CVE-2011-0212",
    "CVE-2011-0213",
    "CVE-2011-0715",
    "CVE-2011-0719",
    "CVE-2011-1132"
  );
  script_bugtraq_id(
    38562,
    39013,
    42599,
    42646,
    43676,
    43819,
    44794,
    44884,
    45164,
    46264,
    46597,
    46734,
    46768,
    47668,
    48418,
    48419,
    48420,
    48422,
    48426,
    48427,
    48429,
    48430,
    48436,
    48437,
    48439,
    48440,
    48442,
    48443,
    48444,
    48445,
    48447
  );
  script_osvdb_id(
    62844,
    63299,
    67378,
    67383,
    68527,
    69265,
    69316,
    69387,
    69390,
    69392,
    69393,
    69394,
    69395,
    69565,
    70847,
    70964,
    71023,
    71268,
    72490,
    73357,
    73358,
    73359,
    73360,
    73361,
    73362,
    73363,
    73365,
    73366,
    73367,
    73368,
    73369,
    73370,
    73371,
    73372,
    73373,
    73375
  );

  script_name(english:"Mac OS X 10.6.x < 10.6.8 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.6.x that is prior
to 10.6.8. This update contains security-related fixes for the
following components :

  - App Store
  - ATS
  - Certificate Trust Policy
  - CoreFoundation
  - CoreGraphics
  - FTP Server
  - ImageIO
  - International Components for Unicode
  - Kernel
  - Libsystem
  - libxslt
  - MobileMe
  - MySQL
  - OpenSSL
  - patch
  - QuickLook
  - QuickTime
  - Samba
  - servermgrd
  - subversion"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4723");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20);
;                 # CVE-2009-3245

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/23");     # OSVDB 62844
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item("Host/OS");
  if (isnull(os)) exit(0, "The 'Host/OS' KB item is missing.");
  if ("Mac OS X" >!< os) exit(0, "The host does not appear to be running Mac OS X.");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


if (ereg(pattern:"Mac OS X 10\.6($|\.[0-7]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
