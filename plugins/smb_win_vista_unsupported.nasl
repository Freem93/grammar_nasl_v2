#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97996);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/17 19:05:07 $");

  script_name(english:"Microsoft Windows Vista Unsupported Installation Detection");
  script_summary(english:"Checks the OS / SMB fingerprint.");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows Vista is running on the remote host. Support for
this operating system was ended by Microsoft on April 11th, 2017.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://support.microsoft.com/en-us/help/22882/windows-vista-end-of-support
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd271028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_vista");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_exclude_keys("Host/not_windows");
  script_require_ports("Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

cpe_ver   = "-";
tag       = "microsoft:windows_vista";
edition   = "";
line_win = "";

os = get_kb_item("Host/OS");
vista = "Windows Vista";

# No OS
if (!os) audit(AUDIT_HOST_NOT, "running an OS known to this plugin");

# Not Windows Vista
if (vista >!< os) audit(AUDIT_OS_NOT, vista);

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
      if (vista >!< line) exit(0, "The OS fingerprint is too fuzzy.");
    }
  }
  else exit(0, "The OS fingerprinting confidence level is too low.");
}

# Find the main OS description line
foreach line (split(os, keep:0))
{
  if (vista >< line)
  {
    line_win = line;
    break;
  }
}

# get service pack
sp_kb = get_kb_item("SMB/CSDVersion");
sp = '';
if (!isnull(sp_kb))
{
  match = pregmatch(string:sp_kb, pattern:'^Service Pack ([0-9])$');
  if (!isnull(match)) sp = match[1];
}

if (sp == '')
{
  match = pregmatch(string:line_win, pattern:'Service Pack ([0-9])$');
  if (!isnull(match)) sp = match[1];
}

if (sp == '') cpe_ver += ':*';
else cpe_ver += ':sp' + sp;

# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
arch = get_kb_item("SMB/ARCH");
if (!isnull(arch) && "x64" >< arch) edition = "x64";
else
{
  if ("x64" >< line_win) edition = "x64";
  else edition = "x86";
}

# Check for any further details about the OS edition.
# Windows Vista editions :
#   - Normal/Standard (signified by nothing extra, just 'Windows Vista')
#   - Ultimate
#   - Enterprise
#   - Home Premium
line_win = tolower(line_win);
if ("ultimate" >< line_win)
  edition += "-ultimate";
else if ("enterprise" >< line_win)
  edition += "-enterprise";
else if ("home premium" >< line_win)
  edition += "-home_premium";

cpe_ver += ":" + edition;

set_kb_item(name:"Host/WinVista", value:"TRUE");

register_unsupported_product(
  product_name : vista,
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : tag,
  version      : cpe_ver
);

security_hole(0);
