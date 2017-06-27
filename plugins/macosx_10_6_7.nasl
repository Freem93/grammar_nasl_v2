#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);    # Avoid problems with large number of xrefs.


include("compat.inc");


if (description)
{
  script_id(52754);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2006-7243",
    "CVE-2010-0405",
    "CVE-2010-1323",
    "CVE-2010-1324",
    "CVE-2010-1452",
    "CVE-2010-2068",
    "CVE-2010-2950",
    "CVE-2010-3069",
    "CVE-2010-3089",
    "CVE-2010-3315",
    "CVE-2010-3434",
    "CVE-2010-3709",
    "CVE-2010-3710",
    "CVE-2010-3801",
    "CVE-2010-3802",
    "CVE-2010-3814",
    "CVE-2010-3855",
    "CVE-2010-3870",
    "CVE-2010-4008",
    "CVE-2010-4009",
    "CVE-2010-4020",
    "CVE-2010-4021",
    "CVE-2010-4150",
    "CVE-2010-4260",
    "CVE-2010-4261",
    "CVE-2010-4409",
    "CVE-2010-4479",
    "CVE-2010-4494",
    "CVE-2011-0170",
    "CVE-2011-0172",
    "CVE-2011-0173",
    "CVE-2011-0174",
    "CVE-2011-0175",
    "CVE-2011-0176",
    "CVE-2011-0177",
    "CVE-2011-0178",
    "CVE-2011-0179",
    "CVE-2011-0180",
    "CVE-2011-0181",
    "CVE-2011-0182",
    "CVE-2011-0183",
    "CVE-2011-0184",
    "CVE-2011-0186",
    "CVE-2011-0187",
    "CVE-2011-0188",
    "CVE-2011-0189",
    "CVE-2011-0190",
    "CVE-2011-0191",
    "CVE-2011-0192",
    "CVE-2011-0193",
    "CVE-2011-0194",
    "CVE-2011-1417"
  );
  script_bugtraq_id(
    40827,
    43212,
    43555,
    43926,
    44214,
    44605,
    44643,
    44718,
    44779,
    44980,
    45116,
    45117,
    45118,
    45119,
    45122,
    45152,
    46832,
    46965,
    46966,
    46971,
    46972,
    46973,
    46982,
    46984,
    46987,
    46988,
    46989,
    46990,
    46991,
    46992,
    46993,
    46994,
    46995,
    46996,
    46997,
    47023
  );
  script_osvdb_id(
    65654,
    66086,
    66745,
    67994,
    68032,
    68035,
    68167,
    68302,
    68328,
    68597,
    68704,
    69109,
    69205,
    69230,
    69513,
    69607,
    69608,
    69609,
    69610,
    69611,
    69612,
    69651,
    69656,
    69660,
    69755,
    69756,
    69757,
    70606,
    71257,
    71479,
    71519,
    71520,
    71521,
    71626,
    71627,
    71628,
    71629,
    71630,
    71631,
    71632,
    71633,
    71634,
    71635,
    71636,
    71637,
    71638,
    71639,
    71640,
    71641,
    71642,
    71643,
    71644
  );
  script_xref(name:"EDB-ID", value:"17901");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"Mac OS X 10.6.x < 10.6.7 Multiple Vulnerabilities");
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
to 10.6.7.

Mac OS X 10.6.7 contains security fixes for the following products :

  - AirPort
  - Apache
  - AppleScript
  - ATS
  - bzip2
  - CarbonCore
  - ClamAV
  - CoreText
  - File Quarantine
  - HFS
  - ImageIO
  - Image RAW
  - Installer
  - Kerberos
  - Kernel
  - Libinfo
  - libxml
  - Mailman
  - PHP
  - QuickLook
  - QuickTime
  - Ruby
  - Samba
  - Subversion
  - Terminal
  - X11"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4581"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00006.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X 10.6.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");    # OSVDB 70606
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"II");
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


if (ereg(pattern:"Mac OS X 10\.6($|\.[0-6]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
