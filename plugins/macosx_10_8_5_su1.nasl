#TRUSTED 100c9589446c5a5ddb1baf3a81806715e9ee5bb17c7b921362e3afaa8320a805e10357a046a989ef4e45fac428c049749b1c5508375f3a10508de0337e3f3dec1ccfe744a2ed52f188c88ecc1945c532aa7b117c484506ae09ad60649df1bab930567acf4699c40565dde2c3a7955d8ee500d411e74d7178be9825073bca50fe675eb7d1a019ddceaa0f2905c86cd66c2baee5fa2018dc87ebbfbbe9f2a846ce9382f718075056645bd25fb3ce433b907a50154e163c580216bb4f553b25311b15575612882ce381e2346dfbaa57a9ccf8535d853ff15f38d91fd88966e52877aeee1c20cd776e770308f3c0398308117fe4817a2397b069b8edb1bfee2354b588b01b34bdee879222e43adabf8dc5cd30325edd5829f4c4092dc9017b03689fc144d38c09a55b655a2f77ba400bd899d81fec30975c029563fca763e940115eb95ab6436a068fa45a4dd1412a541b2df18a02d577e116078b94b002542b13f2673a1d83c0e65ccc0aa8188d26c67bcaba133a313722860987dc7bd203ed96dde60344fcc10939cf44994dcd09a603694b619c3c8b67207c69bf3ed68964204a376e1542a18bf38e87126aa1d3a24458d3f5febf09b6dd142a89b07bdf72cefa69a12e56630895418e30a89391ba7d63547b14be20e539c0ce916669e1fc3ceecabfcf032eb8379077bb6906f1401c5f2719a7d471a543cefb6de2f7ac773ebf
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70301);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/04");

  script_cve_id("CVE-2013-5163");
  script_bugtraq_id(62812);
  script_osvdb_id(98090);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-03-1");

  script_name(english:"Mac OS X 10.8 < 10.8.5 Supplemental Update");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X security update that fixes a
local security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.8 that is missing
the OS X v10.8.5 Supplemental Update.  This update fixes a logic issue
in verification of authentication credentials by Directory Services,
which could otherwise allow a local attacker to bypass password
validation."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5964");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528980/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Install the OS X v10.8.5 Supplemental Update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8");
if (!ereg(pattern:"Mac OS X 10\.8($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Mountain Lion later than 10.8.5.");


# Get the product build version.
plist = "/System/Library/CoreServices/SystemVersion.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 ProductBuildVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
build = exec_cmd(cmd:cmd);
if (
  !strlen(build) ||
  build !~ "^12F[0-9]+$"
) exit(1, "Failed to extract the ProductBuildVersion from '"+plist+"'.");


if (build =~ "^12F([0-9]|[1-3][0-9]|4[0-4])$")
{
  if (report_verbosity > 0)
  {
    report = '\n  Product version                 : ' + os +
             '\n  Installed product build version : ' + build +
             '\n  Fixed product build version     : 12F45' +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else exit(0, "The host has product build version "+build+" and is not affected.");
