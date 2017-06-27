#TRUSTED 5738ba532746b610cb661fa5e22a472b481a96bcc06f7502d909214476141504a8921ccf7c67a7484475543a5576aed3c4a66eb3432a8367cb0059fce85af4b0e23c5d03d5f38f44f0926d378ee323b3833656f05715277b5db38ad03cfac714df19115e8a8d1f20b20ee8fc4db9192363220dcc58c2da48938d828389277cd710d9d843f50b2bdf27b63c9bbff3344c72baaf534f0928cb4652e2b3d7867cdc9fa688b906da6a038bc3fb3ec15f2587e404447a132ed93c465c2da9eff58e2352ee8c74a172f0c7dbfee52342f8b3d2aba18acce828fab38105532fa6684018920bb72b5bf67884843e970bbc1fa573053d6b22b9fea9c7524b19c4d599265eaa2f592b027addb5e0086df7b6531208f2cca2e82ab9942a561eb534f4d9252c13380323fe5ec85166441558aefa49d24bc4202bfe9fb25e507f77869b6c78addaa4dda6f670c3d13dc366577a50da0641bc472ee9b05b5626513676b08087544aa691998a45593508c86b2a74322e78ebc3f80d5747f1bac24784fce8e325b584e023162e5cb15a0bbd73acebf985f9e3ca3eef0af9ec27b41f78b8e03e7bccfac0dd317d976e8f36b1e669604b4f54bc3003225334e567137111cdb40aed4c7900cc7dd3c2e2111dd7ac53332ef5be1e85c88747eed67cb33976eba4c39e85b715850734b498d3dd53d95ca155db0bf14a00598b0121e2c1899972eed13ab4
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(55458);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/06/14");

  script_cve_id(
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0862",
    "CVE-2011-0863",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0867",
    "CVE-2011-0868",
    "CVE-2011-0869",
    "CVE-2011-0871",
    "CVE-2011-0873"
  );
  script_bugtraq_id(
    48137,
    48138,
    48140,
    48144,
    48145,
    48147,
    48148,
    48149
  );
  script_osvdb_id(
    73069,
    73070,
    73073,
    73074,
    73075,
    73076,
    73077,
    73081,
    73083,
    73084,
    73085,
    73176
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 10");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 10, which updates the Java version to
1.6.0_26 / 1.5.0_30.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.5 Update 10, which includes version
12.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (!ereg(pattern:"Mac OS X 10\.5([^0-9]|$)", string:os)) 
  exit(0, "The host is running "+os+" and therefore is not affected.");


plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = 
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.9.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 9)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.9.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since it is running Mac OS X 10.5 and has JavaVM Framework version "+version+".");
