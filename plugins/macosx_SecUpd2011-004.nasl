#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55415);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2010-2632",
    "CVE-2010-3069",
    "CVE-2010-3677",
    "CVE-2010-3682",
    "CVE-2010-3833",
    "CVE-2010-3834",
    "CVE-2010-3835",
    "CVE-2010-3836",
    "CVE-2010-3837",
    "CVE-2010-3838",
    "CVE-2010-4651",
    "CVE-2011-0195",
    "CVE-2011-0196",
    "CVE-2011-0197",
    "CVE-2011-0200",
    "CVE-2011-0202",
    "CVE-2011-0204",
    "CVE-2011-0205",
    "CVE-2011-0212",
    "CVE-2011-0715",
    "CVE-2011-0719"
  );
  script_bugtraq_id(
    42599,
    42646,
    43212,
    43676,
    43819,
    46597,
    46734,
    46768,
    47668,
    48415,
    48416,
    48427,
    48437,
    48439,
    48443,
    48445
  );
  script_osvdb_id(
    67378,
    67383,
    67994,
    68527,
    69387,
    69390,
    69392,
    69393,
    69394,
    69395,
    70964,
    71023,
    71268,
    72490,
    73356,
    73357,
    73360,
    73364,
    73366,
    73368,
    73369
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2011-004)");
  script_summary(english:"Check for the presence of Security Update 2011-004");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes several
security issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 that does not
have Security Update 2011-004 applied. This update contains security-
related fixes for the following components :

  - AirPort
  - App Store
  - ColorSync
  - CoreGraphics
  - ImageIO
  - Libsystem
  - libxslt
  - MySQL
  - patch
  - Samba
  - servermgrd
  - subversion");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4723");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2011-004 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");     
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/packages", "Host/MacOSX/Version");

  exit(0);
}


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


if (ereg(pattern:"Mac OS X 10\.5([^0-9]|$)", string:os))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2011\.00[4-9]|201[2-9]\.[0-9]+)(\.leopard)?\.bom", string:packages))
    exit(0, "The host has Security Update 2011-004 or later installed and therefore is not affected.");
  else
    security_hole(0);
}
else exit(0, "The host is running "+os+" and therefore is not affected.");
