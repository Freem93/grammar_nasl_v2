#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47709);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/21 20:34:21 $");

  script_name(english:"Microsoft Windows 2000 Unsupported Installation Detection");
  script_summary(english:"Checks the OS / SMB fingerprint");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Microsoft Windows that is no
longer supported by Microsoft.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Windows 2000. This operating 
system version is no longer supported by Microsoft.

Lack of support implies that no new security patches for the operating
system will be released by the vendor. As a result, it is likely to
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/lifecycle/?p1=7274");
  # http://blogs.technet.com/b/education/archive/2009/11/10/windows-2000-end-of-life.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e770f996");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_2000");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "smb_nativelanman.nasl");
  script_exclude_keys("Host/not_windows");
  script_require_ports("Host/OS/smb", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

flag = 0;

tag = "microsoft:windows_2000";
cpe_ver = NULL;

os1 = get_kb_item("Host/OS/smb");
if (os1 && "Windows 5.0" >< os1)
{
  macaddr = get_kb_item("SMB/mac_addr");
  if (macaddr)
  {
    if (macaddr == ":::::") exit(0, "While the SMB service identifies itself as 'Windows 2000', the NetBIOS name service shows a MAC address suggesting it's not running Windows.");
    else flag ++;
  }
}

if (!flag)
{
  os = get_kb_item("Host/OS");
  if (!os && !os1) exit(0, "The remote OS is unknown.");

  if ("Windows 2000" >< os)
  {
    conf = int(get_kb_item("Host/OS/Confidence"));
    if (report_paranoia > 1) flag ++;
    else if (conf >= 70)
    {
      flag ++;
      # Check that we did not report other OS or Windows versions
      foreach line (split(os, keep: 0))
        if ("Windows 2000" >!< line) exit(0, "The OS fingerprint is too fuzzy.");
    }
    else exit(0, "The OS fingerprinting confidence level is too low.");

    win2k_line = "";
    foreach line (split(os, keep:FALSE))
    {
      if ("Windows 2000" >< line)
      {
        win2k_line = line;
        break;
      }
    }

    update = NULL;
    if ("Service Pack" >< win2k_line)
    {
      match = eregmatch(pattern:"Service Pack ([0-9]+)$", string:win2k_line);
      if (!isnull(match))
      {
        sp = match[1];
        if (sp > 4) sp = 4;
        update = "sp" + sp;
      }
    }
    else if (get_kb_item("SMB/registry_full_access")) update = "gold";
    if (!isnull(update))
    {
      cpe_ver = update;

      edition = NULL;
      if ("Advanced Server" >< win2k_line)
        edition = "advanced_server";
      else if ("Datacenter Server" >< win2k_line)
        edition = "datacenter_server";
      else if ("Professional" >< win2k_line)
        edition = "professional";
      else if ("Server" >< win2k_line)
        edition = "server";

      if (!isnull(edition))
        cpe_ver += ":" + edition;
    }
  }
}

if (flag)
{
  set_kb_item(name:"Host/Win2000", value:"TRUE");

  register_unsupported_product(product_name:"Windows 2000", cpe_class:CPE_CLASS_OS,
                               cpe_base:tag, version:cpe_ver);

  security_hole(0);
}
else audit(AUDIT_OS_NOT, "Windows 2000");
