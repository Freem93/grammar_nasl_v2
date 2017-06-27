#
# This script has been written by Montgomery County Maryland
# This script is released under GPLv2
#
# For reference, below are the released Internet Explorer versions.
# This information is from:
# http://support.microsoft.com/kb/164539/
#  Version		Product
#
#  4.40.308		Internet Explorer 1.0 (Plus!)
#  4.40.520		Internet Explorer 2.0
#  4.70.1155		Internet Explorer 3.0
#  4.70.1158		Internet Explorer 3.0 (OSR2)
#  4.70.1215		Internet Explorer 3.01
#  4.70.1300		Internet Explorer 3.02 and 3.02a
#  4.71.544		Internet Explorer 4.0 Platform Preview 1.0 (PP1)
#  4.71.1008.3		Internet Explorer 4.0 Platform Preview 2.0 (PP2)
#  4.71.1712.6		Internet Explorer 4.0
#  4.72.2106.8		Internet Explorer 4.01
#  4.72.3110.8		Internet Explorer 4.01 Service Pack 1 (SP1)
#  4.72.3612.1713	Internet Explorer 4.01 Service Pack 2 (SP2)
#  5.00.0518.10		Internet Explorer 5 Developer Preview (Beta 1)
#  5.00.0910.1309	Internet Explorer 5 Beta (Beta 2)
#  5.00.2014.0216	Internet Explorer 5
#  5.00.2314.1003	Internet Explorer 5 (Office 2000)
#  5.00.2614.3500	Internet Explorer 5 (Windows 98 Second Edition)
#  5.00.2516.1900	Internet Explorer 5.01 (Windows 2000 Beta 3, build 5.00.2031)
#  5.00.2919.800	Internet Explorer 5.01 (Windows 2000 RC1, build 5.00.2072)
#  5.00.2919.3800	Internet Explorer 5.01 (Windows 2000 RC2, build 5.00.2128)
#  5.00.2919.6307	Internet Explorer 5.01 (Also included with Office 2000 SR-1, but not installed by default)
#  5.00.2920.0000	Internet Explorer 5.01 (Windows 2000, build 5.00.2195)
#  5.00.3103.1000	Internet Explorer 5.01 SP1 (Windows 2000)
#  5.00.3105.0106	Internet Explorer 5.01 SP1 (Windows 95/98 and Windows NT 4.0)
#  5.00.3314.2101	Internet Explorer 5.01 SP2 (Windows 95/98 and Windows NT 4.0)
#  5.00.3315.1000	Internet Explorer 5.01 SP2 (Windows 2000)
#  5.50.3825.1300	Internet Explorer 5.5 Developer Preview (Beta)
#  5.50.4030.2400	Internet Explorer 5.5 & Internet Tools Beta
#  5.50.4134.0100	Windows Me (4.90.3000)
#  5.50.4134.0600	Internet Explorer 5.5
#  5.50.4308.2900	Internet Explorer 5.5 Advanced Security Privacy Beta
#  5.50.4522.1800	Internet Explorer 5.5 Service Pack 1
#  5.50.4807.2300	Internet Explorer 5.5 Service Pack 2
#  6.00.2462.0000	Internet Explorer 6 Public Preview (Beta)
#  6.00.2479.0006	Internet Explorer 6 Public Preview (Beta) Refresh
#  6.00.2600.0000	Internet Explorer 6
#  6.00.2800.1106	Internet Explorer 6 Service Pack 1 (Windows XP SP1)
#  6.00.2900.2180	Internet Explorer 6 Service Pack 2 (Windows XP SP2)
#  6.00.3663.0000	Internet Explorer 6 for Microsoft Windows Server 2003 RC1
#  6.00.3718.0000	Internet Explorer 6 for Windows Server 2003 RC2
#  6.00.3790.0000	Internet Explorer 6 for Windows Server 2003 (released)
#  6.00.3790.1830	Internet Explorer 6 for Windows Server 2003 SP1 and Windows XP x64
#  6.00.3790.3959	Internet Explorer 6 SP2 for Windows Server 2003 SP1 and Windows XP x64
#  7.00.5730.1100	Internet Explorer 7 for Windows XP and Windows Server 2003
#  7.00.5730.1300	Internet Explorer 7 for Windows XP and Windows Server 2003
#  7.00.6000.16386	Internet Explorer 7 for Windows Vista
#  7.00.6000.16441	Internet Explorer 7 for Windows Server 2003 SP2 x64
#  7.00.6000.16441	Internet Explorer 7 for Windows XP SP2 x64
#  7.00.6001.1800	Internet Explorer 7 for Windows Server 2008 and for Windows Vista SP1
#  8.00.6001.17184	Internet Explorer 8 Beta 1
#  8.00.6001.18241	Internet Explorer 8 Beta 2
#  8.00.6001.18372	Internet Explorer 8 RC1
#  8.00.6001.18702	Internet Explorer 8 for Windows XP, Windows Vista, Windows Server 2003 and Windows Server 2008
#  8.00.7000.00000	Internet Explorer 8 for Windows 7 Beta

# Changes by Tenable:
# - Revised plugin title, updated header notes (10/21/09)
# - Updated to use compat.inc, Added CVSS score (11/18/2009)
# - Updated to use audit.inc, Added more detailed check for IE 6 (05/12/2014)


include("compat.inc");

if (description)
{
 script_id(22024);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/01/25 19:47:13 $");

 script_name(english:"Microsoft Internet Explorer Unsupported Version Detection");
 script_summary(english:"Checks the Internet Explorer version.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Internet Explorer.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft Internet Explorer on the remote Windows host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
 script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/lifecycle#tab2");
 # https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3cf595f");
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Internet Explorer that is currently supported.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
 script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2006-2016 Montgomery County Maryland");

 script_dependencies("smb_login.nasl", "smb_registry_full_access.nasl", "smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access", "SMB/IE/Version");
 exit(0);
}

include("audit.inc");
include("misc_func.inc");

#==================================================================#
# Main code                                                        #
#==================================================================#
warning = 0;

access = get_kb_item_or_exit("SMB/registry_full_access");

# Note: only IE 4.0 and later will be detected by this kb item
version = get_kb_item_or_exit("SMB/IE/Version");

# Check for 4.x, 5.x
if (ereg(pattern:"^[4-8]\.", string:version))
  warning = 1;

os = get_kb_item("SMB/WindowsVersion");
sp = get_kb_item("SMB/CSDVersion");
name = get_kb_item("SMB/ProductName");

if (sp)
{
 sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:sp, replace:"\1");
 sp = int(sp);
}
else sp = 0;

# https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer
if (tolower(name) =~ "(embedded|thin pc|industry update)")
  audit(AUDIT_OS_NOT, "a Windows desktop or server version");

# IE 9 on anything but Vista SP2 or 2008 SP2
if (ereg(pattern:"^[9]\.", string:version))
{
  if (os == "6.0" && sp == 2)
    warning = 0;
  else
    warning = 1;
}

# IE 10 on anything but 2012
if (ereg(pattern:"^10\.", string:version))
{
  if (os == "6.2" && "2012" >< name)
    warning = 0;
  else
    warning = 1;
}


#==================================================================#
# Final Report                                                     #
#==================================================================#


if (warning)
{
  report = string("\n",
    "The remote host has Internet Explorer version ",version,
    " installed.",
    "\n");
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, "Internet Explorer", version);
