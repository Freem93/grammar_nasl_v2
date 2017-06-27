#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88561);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/02/03 20:42:26 $");

  script_name(english:"Microsoft Windows 8 Unsupported Installation Detection");
  script_summary(english:"Checks the OS / SMB fingerprint.");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Windows 8. Support for this
operating system by Microsoft ended January 12th, 2016.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/gp/lifecycle-windows81-faq");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_8");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_exclude_keys("Host/not_windows");
  script_require_ports("Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

cpe_ver   = "";
tag       = "microsoft:windows_8";
edition   = "";
line_win8 = "";

os = get_kb_item("Host/OS");

# No OS
if (!os) audit(AUDIT_HOST_NOT, "running an OS known to this plugin");

# Not Windows 8
if (
  "Windows 8" >!< os
  ||
  # Do not need anchor
  os =~ "Windows 8\.\d"
) audit(AUDIT_OS_NOT, "Windows 8");

# Extra confidence-check for a non-paranoid scan
if (report_paranoia < 2)
{
  conf = int(get_kb_item("Host/OS/Confidence")); # NULL and '' converted to 0
  if (conf >= 70)
  {
    # Check that we did not report other OS or Windows versions, e.g.,
    # a bad (fuzzy) fingerprint will contain several OSes separated by
    # newline :
    #   "some OS\nsome other OS\nyet another OS"
    # If we find an extra line _not_ related to Windows 8 ... bail.
    foreach line (split(os, keep:FALSE))
    {
      if (
        "Windows 8" >!< line
        ||
        # Do not need anchor
        line =~ "Windows 8\.\d"
      ) exit(0, "The OS fingerprint is too fuzzy.");
    }
  }
  else exit(0, "The OS fingerprinting confidence level is too low.");
}

# Find the main OS description line
foreach line (split(os, keep:0))
{
  if (
    "Windows 8" >< line
    &&
    line !~ "Windows 8\.\d"
  )
  {
    line_win8 = line;
    break;
  }
}

# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
if ("x64" >< line_win8) edition = "x64";
else edition = "x86";

# Check for any further details about the OS edition.
# Windows 8 editions :
#   - Normal/Standard (signified by nothing extra, just 'Windows 8')
#   - Professional
#   - Enterprise
#   - Consumer Preview (old)
#   - Itanium
#   - RT (ignored)
# https://blogs.windows.com/windowsexperience/2012/04/16/announcing-the-windows-8-editions/
if ("Pro" >< line_win8)
  edition += "pro";
else if ("Enterprise" >< line_win8)
  edition += "enterprise";
else if ("Itanium" >< line_win8)
  edition += "itanium";
else if ("Consumer" >< line_win8)
  edition += "consumer_preview";

cpe_ver += ":" + edition;

set_kb_item(name:"Host/Win8", value:"TRUE");

register_unsupported_product(
  product_name : "Windows 8",
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : tag,
  version      : cpe_ver
);

security_hole(0);
