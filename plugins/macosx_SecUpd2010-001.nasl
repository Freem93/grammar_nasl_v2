#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(44095);
  script_version("$Revision: 1.11 $");

  script_cve_id(
    "CVE-2009-2285",
    "CVE-2009-3553",
    "CVE-2009-3555",
    "CVE-2009-3794",
    "CVE-2009-3796",
    "CVE-2009-3797",
    "CVE-2009-3798",
    "CVE-2009-3799",
    "CVE-2009-3800",
    "CVE-2009-3951",
    "CVE-2010-0036",
    "CVE-2010-0037"
  );
  script_bugtraq_id(37868, 37869);
  script_osvdb_id(
    55265,
    60204,
    60885,
    60886,
    60887,
    60888,
    60889,
    60890,
    60891,
    61885,
    61886
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2010-001)");
  script_summary(english:"Check for the presence of Security Update 2010-001");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6 or 10.5 that
does not have Security Update 2010-001 applied.

This security update contains fixes for the following products :

  - CoreAudio
  - CUPS
  - Flash Player plug-in
  - ImageIO
  - Image RAW
  - OpenSSL"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4004"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Jan/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/18831"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2010-001 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 119, 189, 200, 310, 399);
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/20");
 script_cvs_date("$Date: 2016/11/28 21:06:39 $");
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
if (ereg(pattern:"^(9\.[0-8]\.|10\.[0-2]\.)", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2010\.00[1-9]|201[1-9]\.[0-9]+)(\.snowleopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2010-001 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
