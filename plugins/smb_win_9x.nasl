#
# (C) Tenable Network Security, Inc.
#

# Thanks to Keith Yong for suggesting this

include("compat.inc");

if (description)
{
  script_id(21626);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Microsoft Windows 95/98/ME Unsupported Installation Detection");
  script_summary(english:"Remote host is running Windows 95/98/ME.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Microsoft Windows that is no
longer supported by Microsoft.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Windows 9x (95, 98,
or ME). Windows 95 support ended on December 31, 2001. Windows 98/ME
support ended on July 11, 2006.

Lack of support implies that no new security patches for the operating
system will be released by the vendor. As a result, it is likely to
contain security vulnerabilities.");
  # https://web.archive.org/web/20131202230706/http://support.microsoft.com/gp/lifean18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b20c1a6c");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%2095&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c3ca148");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%2098&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24903a43");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Millennium%20Edition&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ecdfe69");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_95");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_98");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_me");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (get_kb_item("SMB/transport") == 445) exit(0, "TCP port 445 should not be open on a Windows 9x/ME system.");

os = get_kb_item("Host/OS");
if (! os) exit(0, "The remote OS is unknown.");

flag = 0;

tag = "microsoft:";
cpe_ver = NULL;

if (ereg(pattern:"Windows (95|98|ME)", string:os) )
{
  conf = int(get_kb_item("Host/OS/Confidence"));
  if (report_paranoia > 1) flag ++;
  else if (conf >= 70)
  {
    flag ++;
    # Check that we did not report other OS or Windows versions
    foreach line (split(os, keep: 0))
      if (! ereg(pattern:"Windows (95|98|ME)", string: line) )
        exit(0, "The OS fingerprint is too fuzzy.");
  }
  else exit(0, "The OS fingerprinting confidence level is too low.");

  win9x_line = "";
  foreach line (split(os, keep:FALSE))
  {
    if ("Windows (95|98|ME)" >< line)
    {
      win9x_line = line;
      break;
    }
  }

  if ("Windows ME" >< win9x_line) tag += "windows_me";
  else if ("Windows 95" >< win9x_line) tag += "windows_95";
  else if ("Windows 98" >< win9x_line) tag += "windows_98";

  update = NULL;
  if ("Service Pack" >< win9x_line)
  {
    match = eregmatch(pattern:"Service Pack ([0-9]+)$", string:win9x_line);
    if (!isnull(match)) update = "sp" + match[1];
  }
  else if (get_kb_item("SMB/registry_full_access")) update = "gold";
  if (!isnull(update)) cpe_ver = update;
}

if (!flag) audit(AUDIT_OS_NOT, "Windows 9x");

set_kb_item(name:"Host/Win9x", value: "TRUE");

register_unsupported_product(product_name:"Windows", cpe_class:CPE_CLASS_OS,
                               cpe_base:tag, version:cpe_ver);

security_hole(0);
