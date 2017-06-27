#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(49289);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/06/14 20:11:56 $");

  script_cve_id("CVE-2010-1820");
  script_bugtraq_id(43341);
  script_osvdb_id(68153);

  script_name(english:"Mac OS X AFP Shared Folders Unauthenticated Access (Security Update 2010-006)");
  script_summary(english:"Check for the presence of Security Update 2010-006");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes a security
issue."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6 that does not
have Security Update 2010-006 applied. 

This security update fixes an issue in AFP Server by which a remote
attacker with knowledge of an account name on the affected system
may be able to bypass the password validation and access AFP shared 
folders.

Note that this issue is only exploitable when File Sharing is enabled,
and it is not by default."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4361"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Sep/msg00004.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2010-006 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^10\.[0-4]\.", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2010\.00[6-9]|201[1-9]\.[0-9]+)(\.snowleopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2010-006 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
