#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70093);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/24 19:16:44 $");

  script_cve_id("CVE-2013-0308");
  script_bugtraq_id(58148);
  script_osvdb_id(90610);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-09-18-3");

  script_name(english:"Apple Xcode < 5.0 (Mac OS X)");
  script_summary(english:"Checks version of Xcode");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is prone to a
man-in-the-middle attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host has Apple Xcode prior to 5.0 installed. It,
therefore, includes a version of git in which the imap-send command
reportedly does not verify that a server hostname matches the domain
name in its X.509 certificate.  A man-in-the-middle attacker could
leverage this vulnerability to spoof SSL servers via an arbitrary
valid certificate."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5937");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Sep/msg00007.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528719/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Apple Xcode version 5.0 or later, available for OS X
Mountain Lion 10.8.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Xcode/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

appname = "Apple Xcode";
if (!get_kb_item("MacOSX/Xcode/Installed")) audit(AUDIT_NOT_INST, appname);

kb_base = "MacOSX/Xcode/";
num_installed = get_kb_item_or_exit(kb_base+'NumInstalled');

report = '';
for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base+install_num+'/Path');
  ver = get_kb_item_or_exit(kb_base+install_num+'/Version');
  fix = '5.0';

  if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
}

if (report)
{
  if (report_verbosity > 0) security_warning(port:0, extra:report);
  else security_warning(0);

  exit(0);
}
else exit(0, 'No affected ' +  appname + ' installs were found.');
