#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73182);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_osvdb_id(155633);
  script_xref(name:"EDB-ID", value:"41929");

  script_name(english:"Microsoft Windows XP Unsupported Installation Detection (ERRATICGOPHER)");
  script_summary(english:"Checks the OS / SMB fingerprint.");

  script_set_attribute(attribute:"synopsis", value:
"The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Windows XP. Support for this
operating system by Microsoft ended April 8th, 2014.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+XP&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33ca6af0");
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

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_xp");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_exclude_keys("Host/not_windows");
  script_require_ports("Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

flag = 0;

cpe_ver = NULL;

tag = "microsoft:windows_xp";

os = get_kb_item("Host/OS");
if (!os) exit(0, "The remote OS is unknown.");

if ("Windows XP" >< os)
{
  conf = int(get_kb_item("Host/OS/Confidence"));
  if (report_paranoia > 1)
  {
    # https://www.microsoft.com/windowsembedded/en-us/product-lifecycles.aspx
    xp = egrep(pattern:"Windows XP", string:os);
    xp_embed = egrep(pattern:"Windows XP for Embedded Systems", string:os);
    if (xp == xp_embed) exit(0, "Windows XP for Embedded Systems is supported through January 2016.");

    flag++;
  }
  else if (conf >= 70)
  {
    embedded = 0;
    flag ++;

    # Check that we did not report other OS or Windows versions
    foreach line (split(os, keep: 0))
    {
      if ("Windows XP" >!< line) exit(0, "The OS fingerprint is too fuzzy.");
      if ("Windows XP for Embedded Systems" >< line) embedded++;
    }
    # https://www.microsoft.com/windowsembedded/en-us/product-lifecycles.aspx
    if (embedded)
    {
      if ('\n' >< os) exit(0, "The OS fingerprint isn't granular enough to distinguish between Windows XP and Windows XP for Embedded Systems.");
      else exit(0, "Windows XP for Embedded Systems is supported through January 2016.");
    }
  }
  else exit(0, "The OS fingerprinting confidence level is too low.");

  xp_line = "";
  foreach line (split(os, keep:FALSE))
  {
    if ("Windows XP" >< line)
    {
      xp_line = line;
      break;
    }
  }

  update = NULL;
  if ("Service Pack" >< xp_line)
  {
    match = eregmatch(pattern:"Service Pack ([0-9]+)$", string:xp_line);
    if (!isnull(match)) update = "sp" + match[1];
  }
  else if (get_kb_item("SMB/registry_full_access")) update = "gold";

  if(!isnull(update))
  {
    cpe_ver = update;
    edition = NULL;
    if ("Professional" >< xp_line)
      edition = "professional";
    else if ("Embedded" >< xp_line)
      edition = "embedded";
    else if ("Home" >< xp_line)
      edition = "home";
    else if ("Media Center" >< xp_line)
      edition = "media_center";

    if (!isnull(edition))
      cpe_ver += ":" + edition;
  }
}

if (flag)
{
  set_kb_item(name:"Host/WinXP", value:"TRUE");

  register_unsupported_product(product_name:"Windows XP", cpe_class:CPE_CLASS_OS,
                               cpe_base:tag, version:cpe_ver);
  security_hole(0);
}
else audit(AUDIT_OS_NOT, "Windows XP");
