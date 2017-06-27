#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);    # Avoid problems with large number of xrefs.


include("compat.inc");


if (description)
{
  script_id(52753);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2010-0405",
    "CVE-2010-1323",
    "CVE-2010-1452",
    "CVE-2010-2068",
    "CVE-2010-3089",
    "CVE-2010-3434",
    "CVE-2010-3436",
    "CVE-2010-3709",
    "CVE-2010-3814",
    "CVE-2010-3855",
    "CVE-2010-4008",
    "CVE-2010-4150",
    "CVE-2010-4260",
    "CVE-2010-4261",
    "CVE-2010-4479",
    "CVE-2011-0170",
    "CVE-2011-0181",
    "CVE-2011-0183",
    "CVE-2011-0188",
    "CVE-2011-0191",
    "CVE-2011-0192",
    "CVE-2011-1417"
  );
  script_bugtraq_id(
    40827,
    43555,
    44214,
    44643,
    44718,
    44723,
    44779,
    44980,
    45118,
    45152,
    46832,
    46966,
    46990,
    46996
  );
  script_osvdb_id(
    65654,
    66745,
    68032,
    68035,
    68167,
    68302,
    68704,
    69109,
    69110,
    69205,
    69513,
    69610,
    69611,
    69612,
    69656,
    69660,
    71257,
    71479,
    71519,
    71520,
    71521,
    71636,
    71640
  );
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2011-001)");
  script_summary(english:"Check for the presence of Security Update 2011-001");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.5 that does not
have Security Update 2011-001 applied. 

This security update contains fixes for the following products :

  - Apache
  - bzip2
  - ClamAV
  - ImageIO
  - Kerberos
  - Libinfo
  - libxml
  - Mailman
  - PHP
  - QuickLook
  - Ruby
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
    value:"Install Security Update 2011-001 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(0, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^9\.[0-8]\.", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2011\.00[1-9]|201[2-9]\.[0-9]+)(\.leopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2011-001 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
