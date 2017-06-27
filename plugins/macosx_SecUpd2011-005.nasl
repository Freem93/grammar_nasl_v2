#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(56141);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/05/10 16:20:20 $");

  script_name(english:"Mac OS X Fraudulent DigiNotar Digital Certificates (Security Update 2011-005)");
  script_summary(english:"Check for the presence of Security Update 2011-005");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains support for an untrusted
certificate authority."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6 or 10.7 that
does not have Security Update 2011-005 applied.  Due to the issuance
of several fraudulent SSL certificates, this security update removes
DigiNotar from the list of trusted root certificates as well as the
list of Extended Validation (EV) certificate authorities.  It also
configures default system trust settings so that DigiNotar's
certificates, including those issued by other authorities, are not
trusted."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4920"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2011/Sep/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2011-005 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages", "Host/uname");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


uname = get_kb_item_or_exit("Host/uname");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(0, "Can't identify the Darwin kernel version from the uname output ("+uname+").");

darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^(10\.[0-8]|11\.[01])\.", string:darwin))
{
  packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2011\.00[5-9]|201[2-9]\.[0-9]+)(\.(snowleopard[0-9.]*|lion))?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2011-005 or later installed and therefore is not affected.");
  else 
    security_warning(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
