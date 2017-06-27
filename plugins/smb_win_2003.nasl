#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84729);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_osvdb_id(155633);
  script_xref(name:"EDB-ID", value:"41929");

  script_name(english:"Microsoft Windows Server 2003 Unsupported Installation Detection (ERRATICGOPHER)");
  script_summary(english:"Checks the OS / SMB fingerprint.");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Windows Server 2003. Support for
this operating system by Microsoft ended July 14th, 2015.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://www.microsoft.com/en-us/server-cloud/products/windows-server-2003/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0dbe792");
  # https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?321523eb");
  script_set_attribute(attribute:"see_also", value:"https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/");
  # https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dcab5e4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_2003_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_exclude_keys("Host/not_windows");
  script_require_ports("Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

cpe_ver = NULL;

tag = "microsoft:windows_2003_server";

os = get_kb_item("Host/OS");

if (!os) exit(0, "The remote OS is unknown.");

if ("Windows Server 2003" >< os)
{
  if (report_paranoia <= 1)
  {
    conf = int(get_kb_item("Host/OS/Confidence"));
    if (conf >= 70)
    {
      foreach line (split(os, keep:FALSE))
      {
        if ("Windows Server 2003" >!< line) exit(0, "The OS fingerprint is too fuzzy.");
      }
    }
    else exit(0, "The OS fingerprinting confidence level is too low.");
  }
}
else audit(AUDIT_OS_NOT, "Windows 2003");

line_2003 = "";
foreach line (split(os, keep:0))
{
  if ("Windows Server 2003" >< line)
  {
    line_2003 = line;
    break;
  }
}

update = "";
if ("R2" >< line_2003) update = 'r2';

if ("Service Pack" >< line_2003)
{
  if (!empty(update)) update += "_sp";
  else update += "sp";

  match = eregmatch(pattern:"Service Pack ([0-9]+)$", string:line_2003);
  if (!isnull(match)) update += match[1];
  else exit(1, "Unable to obtain service pack number.");
}
else if (get_kb_item("SMB/registry_full_access")) update = "gold";

if(!empty(update))
{
  cpe_ver = update;
  edition = "";

  if ("x64" >< line_2003) edition = "x64";

  if ("Standard" >< line_2003)
    edition += "standard";
  else if ("Enterprise" >< line_2003)
    edition += "enterprise";
  else if ("Datacenter" >< line_2003)
    edition += "datacenter";
  else if ("Compute Cluster" >< line_2003)
    edition += "compute_cluster";
  else if ("Storage" >< line_2003)
    edition += "storage";
  else if ("Itanium" >< line_2003)
    edition += "itanium";

  if (!empty(edition))
    cpe_ver += ":" + edition;
}

set_kb_item(name:"Host/Win2003", value:"TRUE");

register_unsupported_product(
  product_name : "Windows 2003",
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : tag,
  version      : cpe_ver
);

security_hole(0);
