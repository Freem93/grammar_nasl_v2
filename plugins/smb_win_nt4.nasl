#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19699);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Microsoft Windows NT 4.0 Unsupported Installation Detection");
  script_summary(english:"Remote Host is running Windows NT 4.0.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Microsoft Windows that is no
longer supported by Microsoft.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Windows NT 4.0. This operating 
system version is no longer supported by Microsoft.

Lack of support implies that no new security patches for the operating
system will be released by the vendor. As a result, it is likely to
contain security vulnerabilities.");
  # https://web.archive.org/web/20060203235129/http://www.microsoft.com/ntserver/ProductInfo/Availability/Retiring.asp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1bdda6e");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=microsoft%20windows%20nt&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aead47fa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_nt:4.0");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("os_fingerprint.nasl", "smb_nativelanman.nasl");
  script_exclude_keys("Host/not_windows");
  script_require_ports("Host/OS/smb", "Host/OS");
  exit (0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

if (get_kb_item("SMB/transport") == 445)
 exit(0, "TCP port 445 should not be open on a Windows NT4 system.");

flag = 0;

tag = "microsoft:windows_nt";
cpe_ver = "4.0";

os1 = get_kb_item ("Host/OS/smb") ;
if ("Windows 4.0" >< os1)
  flag ++;
else
{
  os = get_kb_item("Host/OS");
  if ("Windows NT 4.0" >< os )
  {
    conf = int(get_kb_item("Host/OS/Confidence"));
    if (report_paranoia > 1) flag ++;
    else if (conf >= 70)
    {
      flag ++;
      # Check that we did not report other OS or Windows versions
      foreach line (split(os, keep: 0))
        if ("Windows NT 4.0" >!< line)
	  exit(0, "The OS fingerprint is too fuzzy.");
    }
    else exit(0, "The OS fingerprinting confidence level is too low.");

    winnt_line = "";
    foreach line (split(os, keep:FALSE))
    {
      if ("Windows NT 4.0" >< line)
      {
        winnt_line = line;
        break;
      }
    }

    update = NULL;
    if ("Service Pack" >< winnt_line)
    {
      match = eregmatch(pattern:"Service Pack ([0-9]+[Aa]?)$", string:winnt_line);
      if (!isnull(match)) update = "sp" + tolower(match[1]);
    }
    else if (get_kb_item("SMB/registry_full_access")) update = "gold";
    if (!isnull(update))
    {
      cpe_ver += ":" + update;

      edition = NULL;
      if ("Embedded" >< winnt_line)
        edition = "embedded";
      if ("Enterprise" >< winnt_line)
        edition = "enterprise";
      else if ("Terminal Server" >< winnt_line)
        edition = "terminal_server";
      else if ("Server" >< winnt_line)
        edition = "server";
      else if ("Workstation" >< winnt_line)
        edition = "workstation";

      if (!isnull(edition))
        cpe_ver += ":" + edition;
    }
  }
}

if (!flag) audit(AUDIT_OS_NOT, "Windows NT 4.0");

set_kb_item(name:"Host/WinNT4", value: "TRUE");

register_unsupported_product(product_name:"Windows NT", cpe_class:CPE_CLASS_OS,
                             cpe_base:tag, version:cpe_ver);

security_hole(0);
