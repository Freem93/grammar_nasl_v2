#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(45542);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/06 18:55:25 $");

  script_cve_id("CVE-2010-1120");
  script_bugtraq_id(38955);
  script_osvdb_id(63472);

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2010-003)");
  script_summary(english:"Check for the presence of Security Update 2010-003");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes a security
issue."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.6 or 10.5 that
does not have Security Update 2010-003 applied.

This security update contains a fix for an issue in Apple Type
Services involving its handling of embedded fonts.  If an attacker can
trick a user into viewing or downloading a document containing a
specially crafted embedded font, this issue could be leveraged to
execute arbitrary code on the affected system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dvlabs.tippingpoint.com/blog/2010/02/15/pwn2own-2010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://twitter.com/thezdi/statuses/11002504493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/Apr/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install Security Update 2010-003 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^(9\.[0-8]\.|10\.[0-3]\.)", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2010\.00[3-9]|201[1-9]\.[0-9]+)(\.snowleopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2010-003 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
