#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62758);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/14 00:06:13 $");

  script_name(english:"Microsoft XML Parser (MSXML) and XML Core Services Unsupported");
  script_summary(english:"Checks the version of MSXML DLL files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains unsupported XML parsers.");
  script_set_attribute(attribute:"description", value:
"The remote host contains one or more unsupported versions of the
Microsoft XML Parser (MSXML) or XML Core Services.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that support for MSXML 3.0 and 6.0 is based on the support policy
of the operating system on which it is installed. Support for MSXML
5.0 is based on the Microsoft Office lifecycle policy.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the software packages responsible for the unsupported DLL
versions or upgrade to a supported version of Windows (Vista / 2008 or
later). Alternatively, uninstall the outdated MSXML or XML Core
Services.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/269238");
  script_set_attribute(attribute:"see_also", value:"https://msdn.microsoft.com/en-us/library/jj152146(v=vs.85).aspx");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
vers = get_kb_item_or_exit("SMB/WindowsVersion");
arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);

# Unsupported Windows versions
eol_os      = NULL;
eol_os_date = NULL;

if      ('4.0' >< vers) eol_os_date = '2004/12/31 (end of support date for Windows NT 4.0)';
else if ('5.0' >< vers) eol_os_date = '2010/07/13 (end of support date for Windows 2000)';
else if ('5.1' >< vers) eol_os_date = '2014/04/08 (end of support date for Windows XP)';
else if ('5.2' >< vers) eol_os_date = '2015/07/14 (end of support date for Windows Server 2003)';

# Check if host is Windows 2003 64-bit
win2k3x64 = FALSE;
if ('5.2' >< vers && arch  == "x64")
{
  productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
  if ("2003" >< productname)
    win2k3x64 = TRUE;
}

eol_data = make_array();

currently_supported_versions =
  "5.20.1076 (Office 2007) / 6.0 or later on a supported version of Windows (Vista / 2008 or later).";

# The data is a standard grouping of EOL data
# grouped by version number grouped by file name.
#  - EOL data elements are product_version, eol_date,
#    and eol_announcement (a URL).
# Example:
#  msxml[0-9].dll {
#    version {
#      product_version
#      eol_date
#      eol_announcement
#    }
#    ...
#    version {
#      product_version
#      eol_date
#      eol_announcement
#    }
#  ...
#
# To add a 'still supported' range, copy a standard
# grouping, set eol_date and eol_announcement to NULL.

##################################################
# 1.x                                            #
##################################################
# 1.0
eol_data['msxml.dll']['4.71.1712.5']['product_version']='1.0';
eol_data['msxml.dll']['4.71.1712.5']['eol_date']='2007/04/10';
eol_data['msxml.dll']['4.71.1712.5']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 1.0a
eol_data['msxml.dll']['4.72.2106.4']['product_version']='1.0a';
eol_data['msxml.dll']['4.72.2106.4']['eol_date']='2007/04/10';
eol_data['msxml.dll']['4.72.2106.4']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 1.0 SP1
eol_data['msxml.dll']['4.72.3110.0']['product_version']='1.0 SP1';
eol_data['msxml.dll']['4.72.3110.0']['eol_date']='2007/04/10';
eol_data['msxml.dll']['4.72.3110.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';

##################################################
# 2.x                                            #
##################################################
# 2.0
eol_data['msxml.dll']['5.0.2014.0206']['product_version']='2.0';
eol_data['msxml.dll']['5.0.2014.0206']['eol_date']='2007/04/10';
eol_data['msxml.dll']['5.0.2014.0206']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.0a
eol_data['msxml.dll']['5.0.2314.1000']['product_version']='2.0a';
eol_data['msxml.dll']['5.0.2314.1000']['eol_date']='2007/04/10';
eol_data['msxml.dll']['5.0.2314.1000']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.0b
eol_data['msxml.dll']['5.0.2614.3500']['product_version']='2.0b';
eol_data['msxml.dll']['5.0.2614.3500']['eol_date']='2007/04/10';
eol_data['msxml.dll']['5.0.2614.3500']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.5 Beta 2
eol_data['msxml.dll']['5.0.2919.38']['product_version']='2.5 Beta 2';
eol_data['msxml.dll']['5.0.2919.38']['eol_date']='2007/04/10';
eol_data['msxml.dll']['5.0.2919.38']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.5a
eol_data['msxml.dll']['5.0.2919.6303']['product_version']='2.5a';
eol_data['msxml.dll']['5.0.2919.6303']['eol_date']='2007/04/10';
eol_data['msxml.dll']['5.0.2919.6303']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.5
eol_data['msxml.dll']['5.0.2920.0']['product_version']='2.5';
eol_data['msxml.dll']['5.0.2920.0']['eol_date']='2007/04/10';
eol_data['msxml.dll']['5.0.2920.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.5 SP1
eol_data['msxml.dll']['8.0.5226']['product_version']='2.5 SP1';
eol_data['msxml.dll']['8.0.5226']['eol_date']='2007/04/10';
eol_data['msxml.dll']['8.0.5226']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.5 SP2
eol_data['msxml.dll']['8.0.5718.1']['product_version']='2.5 SP2';
eol_data['msxml.dll']['8.0.5718.1']['eol_date']='2007/04/10';
eol_data['msxml.dll']['8.0.5718.1']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.6 (SQL Server 2000 Beta 2)
eol_data['msxml.dll']['8.0.5207.3']['product_version']='2.6 Beta 2';
eol_data['msxml.dll']['8.0.5207.3']['eol_date']='2008/04/08';
eol_data['msxml.dll']['8.0.5207.3']['eol_announcement']='http://support.microsoft.com/lifecycle/?p1=2852';
# 2.6 (MDAC 2.6 / SQL Server 2000 SP0 / BizTalk (Tech Preview / Beta))
eol_data['msxml.dll']['8.0.6518.1']['product_version']='2.6 (MDAC 2.6)';
eol_data['msxml.dll']['8.0.6518.1']['eol_date']='2008/04/08';
eol_data['msxml.dll']['8.0.6518.1']['eol_announcement']='http://support.microsoft.com/lifecycle/?p1=2852';
# 2.5 Post SP2 (IE 5.5 SP2 / Windows 95)
eol_data['msxml.dll']['8.00.6611.1']['product_version']='2.5 Post SP2';
eol_data['msxml.dll']['8.00.6611.1']['eol_date']='2001/12/31';
eol_data['msxml.dll']['8.00.6611.1']['eol_announcement']='http://support.microsoft.com/lifecycle/?p1=7864';
# 2.5 SP3
eol_data['msxml.dll']['8.00.6730.0']['product_version']='2.5 SP3';
eol_data['msxml.dll']['8.00.6730.0']['eol_date']='2007/04/10';
eol_data['msxml.dll']['8.00.6730.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 1.x found on Windows XP SP3
eol_data['msxml.dll']['8.00.7002.0']['product_version']='1.x (Windows XP SP3)';
eol_data['msxml.dll']['8.00.7002.0']['eol_date']='2007/04/10';
eol_data['msxml.dll']['8.00.7002.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.6 Web Release
eol_data['msxml2.dll']['7.50.4920.0']['product_version']='2.6 Web Release';
eol_data['msxml2.dll']['7.50.4920.0']['eol_date']='2007/04/10';
eol_data['msxml2.dll']['7.50.4920.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.6 SP1
eol_data['msxml2.dll']['8.1.7502.0']['product_version']='2.6 SP1';
eol_data['msxml2.dll']['8.1.7502.0']['eol_date']='2007/04/10';
eol_data['msxml2.dll']['8.1.7502.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.6 SP2
eol_data['msxml2.dll']['8.2.8307.0']['product_version']='2.6 SP2';
eol_data['msxml2.dll']['8.2.8307.0']['eol_date']='2007/04/10';
eol_data['msxml2.dll']['8.2.8307.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.0 SP3 found on  Windows Server 2003 SP3
eol_data['msxml2.dll']['8.30.9528.0']['product_version']='2.0 SP3 (Windows Server 2003 SP3)';
eol_data['msxml2.dll']['8.30.9528.0']['eol_date']= '2007/04/10';
eol_data['msxml2.dll']['8.30.9528.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.0 SP3 found on Windows XP SP3
eol_data['msxml2.dll']['8.30.9529.0']['product_version']='2.0 SP3 (Windows XP SP3)';
eol_data['msxml2.dll']['8.30.9529.0']['eol_date']= '2007/04/10';
eol_data['msxml2.dll']['8.30.9529.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# All 1.x and 2.x are no longer supported by Microsoft
# Need to flag them all regardless of version
# 1.x All
# Note: currently XP and Server 2003 contain msxml.dll
# and msxml2.dll files from standard installs. These files
# are not removed by standard patching processes so we do
# not currently want to report against those versions, thus
# the following false ceiling is commented out.

eol_data['msxml.dll']['99.99.9999.9']['product_version']='1.x';
eol_data['msxml.dll']['99.99.9999.9']['eol_date']= '2007/04/10';
eol_data['msxml.dll']['99.99.9999.9']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 2.x All
eol_data['msxml2.dll']['99.99.9999.9']['product_version']='2.x';
eol_data['msxml2.dll']['99.99.9999.9']['eol_date']= '2007/04/10';
eol_data['msxml2.dll']['99.99.9999.9']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';

##################################################
# 3.x                                            #
# Note : 3.x follows the support policy of the   #
#        OS into which it is built.              #
#        - 3.0 SP9 shipped with Windows XP SP3   #
##################################################
if (!isnull(eol_os_date))
{
  # 3.0 Web Release
  eol_data['msxml3.dll']['7.50.5108.0']['product_version']='3.0 Web Release';
  eol_data['msxml3.dll']['7.50.5108.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['7.50.5108.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 Web Release (May 2000)
  eol_data['msxml3.dll']['8.0.7309.3']['product_version']='3.0 Web Release (May 2000)';
  eol_data['msxml3.dll']['8.0.7309.3']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.0.7309.3']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 Web Release (July 2000)
  eol_data['msxml3.dll']['8.0.7520.1']['product_version']='3.0 Web Release (July 2000)';
  eol_data['msxml3.dll']['8.0.7520.1']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.0.7520.1']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 Web Release (September 2000)
  eol_data['msxml3.dll']['8.0.7728.0']['product_version']='3.0 Web Release (September 2000)';
  eol_data['msxml3.dll']['8.0.7728.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.0.7728.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0
  eol_data['msxml3.dll']['8.0.7820.0']['product_version']='3.0';
  eol_data['msxml3.dll']['8.0.7820.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.0.7820.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP1
  eol_data['msxml3.dll']['8.10.8308.0']['product_version']='3.0 SP1';
  eol_data['msxml3.dll']['8.10.8308.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.10.8308.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP2
  eol_data['msxml3.dll']['8.20.8730.1']['product_version']='3.0 SP2';
  eol_data['msxml3.dll']['8.20.8730.1']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.20.8730.1']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP3
  eol_data['msxml3.dll']['8.30.9926.0']['product_version']='3.0 SP3';
  eol_data['msxml3.dll']['8.30.9926.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.30.9926.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP4
  eol_data['msxml3.dll']['8.40.9419.0']['product_version']='3.0 SP4';
  eol_data['msxml3.dll']['8.40.9419.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.40.9419.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP5
  eol_data['msxml3.dll']['8.50.2162.0']['product_version']='3.0 SP5';
  eol_data['msxml3.dll']['8.50.2162.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.50.2162.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP7
  eol_data['msxml3.dll']['8.70.1104']['product_version']='3.0 SP7';
  eol_data['msxml3.dll']['8.70.1104']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.70.1104']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 Post SP7 (MS06-061)
  eol_data['msxml3.dll']['8.70.1113.0']['product_version']='3.0 Post SP7 (MS06-061)';
  eol_data['msxml3.dll']['8.70.1113.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.70.1113.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 Post SP8
  eol_data['msxml3.dll']['8.80.1185.0']['product_version']='3.0 Post SP8';
  eol_data['msxml3.dll']['8.80.1185.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.80.1185.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP9 - shipped with XP SP3 / Server 2003
  eol_data['msxml3.dll']['8.90.1002.0']['product_version']='3.0 SP9';
  eol_data['msxml3.dll']['8.90.1002.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.90.1002.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 Post SP9 (MS06-061) - is still supported on Vista
  eol_data['msxml3.dll']['8.90.1101.0']['product_version']='3.0 Post SP9';
  eol_data['msxml3.dll']['8.90.1101.0']['eol_date']= eol_os_date;
  eol_data['msxml3.dll']['8.90.1101.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 3.0 SP10 (on Vista SP1) - is still supported
  # 3.0 SP10 (on Vista SP2) - is still supported
  # 3.0 SP10 (on XP SP3) / 8.100.1053.0 - is still supported
  # 3.0 Post SP10 (KB973687) - is still supported
  # 3.0 SP11 - is still supported
  # 3.0 Post SP11 (MS10-051) - is still supported

  # Also check for Wmsxml3.dll (32-bit versions of MSXML 3.0 on 64-bit Windows Server 2003)
  if (win2k3x64)
  { 
    foreach ver (keys(eol_data['msxml3.dll']))
    {
      foreach info (keys(eol_data['msxml3.dll'][ver]))
      {
        eol_data['wmsxml3.dll'][ver][info] = eol_data['msxml3.dll'][ver][info];
      }
    }
  }
}

##################################################
# 4.x                                            #
##################################################
# 4.0
eol_data['msxml4.dll']['4.0.9004.0']['product_version']='4.0';
eol_data['msxml4.dll']['4.0.9004.0']['eol_date']='2010/04/01';
eol_data['msxml4.dll']['4.0.9004.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 4.0 SP1
eol_data['msxml4.dll']['4.10.9404.0']['product_version']='4.0 SP1';
eol_data['msxml4.dll']['4.10.9404.0']['eol_date']='2010/04/01';
eol_data['msxml4.dll']['4.10.9404.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 4.0 SP2
eol_data['msxml4.dll']['4.20.9818.0']['product_version']='4.0 SP2';
eol_data['msxml4.dll']['4.20.9818.0']['eol_date']='2010/04/13';
eol_data['msxml4.dll']['4.20.9818.0']['eol_announcement']='http://download.microsoft.com/download/A/2/D/A2D8587D-0027-4217-9DAD-38AFDB0A177E/MSXML4%20SP3%20RTM%20Release%20Note.htm';
# 4.0 Post SP2 (MS06-061)
eol_data['msxml4.dll']['4.20.9839.0']['product_version']='4.0 Post SP2 (MS06-061)';
eol_data['msxml4.dll']['4.20.9839.0']['eol_date']='2010/04/13';
eol_data['msxml4.dll']['4.20.9839.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 4.0 Post SP2 (MS06-071)
eol_data['msxml4.dll']['4.20.9841.0']['product_version']='4.0 Post SP2 (MS06-071)';
eol_data['msxml4.dll']['4.20.9841.0']['eol_date']='2010/04/13';
eol_data['msxml4.dll']['4.20.9841.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 4.0 Post SP2 (MS07-042)
eol_data['msxml4.dll']['4.20.9848.0']['product_version']='4.0 Post SP2 (MS07-042)';
eol_data['msxml4.dll']['4.20.9848.0']['eol_date']='2010/04/13';
eol_data['msxml4.dll']['4.20.9848.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 4.0 Post SP2 (KB973688)
eol_data['msxml4.dll']['4.20.9876.0']['product_version']='4.0 Post SP2 (KB973688)';
eol_data['msxml4.dll']['4.20.9876.0']['eol_date']='2010/04/13';
eol_data['msxml4.dll']['4.20.9876.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
# 4.0 SP3
eol_data['msxml4.dll']['4.30.2100.0']['product_version']='4.0 SP3';
eol_data['msxml4.dll']['4.30.2100.0']['eol_date']='2014/04/12';
eol_data['msxml4.dll']['4.30.2100.0']['eol_announcement']='https://support.microsoft.com/en-us/lifecycle/search/7921';
# 4.0 Post SP3 (KB2758694)
eol_data['msxml4.dll']['4.30.2107.0']['product_version']='4.0 Post SP3 (KB2758694)';
eol_data['msxml4.dll']['4.30.2107.0']['eol_date']='2014/04/12';
eol_data['msxml4.dll']['4.30.2107.0']['eol_announcement']='https://support.microsoft.com/en-us/lifecycle/search/7921';
# 4.0 Post SP3 (KB2758694)
eol_data['msxml4.dll']['4.30.2117.0']['product_version']='4.0 Post SP3 (KB2758694)';
eol_data['msxml4.dll']['4.30.2117.0']['eol_date']='2014/04/12';
eol_data['msxml4.dll']['4.30.2117.0']['eol_announcement']='https://support.microsoft.com/en-us/lifecycle/search/7921';

##################################################
# 5.x                                            #
# Note : If version is greater than a currently  #
#        supported version, it is considered     #
#        still in support since 5.x follows the  #
#        support cycle of Office/SharePoint      #
#        installs.                               #
##################################################
# 5.0 (Office 2003)
eol_data['msxml5.dll']['5.0.2916.0']['product_version']='5.0 (Office 2003)';
eol_data['msxml5.dll']['5.0.2916.0']['eol_date']='2005/07/27';
eol_data['msxml5.dll']['5.0.2916.0']['eol_announcement']='http://support.microsoft.com/lifecycle/?p1=2488';
# 5.0 (Office 2003 SP1)
eol_data['msxml5.dll']['5.10.2925.0']['product_version']='5.0 (Office 2003 SP1)';
eol_data['msxml5.dll']['5.10.2925.0']['eol_date']='2006/10/10';
eol_data['msxml5.dll']['5.10.2925.0']['eol_announcement']='http://support.microsoft.com/lifecycle/?p1=2488';
# 5.0 (Office 2003 SP2)
eol_data['msxml5.dll']['5.10.2927.0']['product_version']='5.0 (Office 2003 SP2)';
eol_data['msxml5.dll']['5.10.2927.0']['eol_date']='2008/10/14';
eol_data['msxml5.dll']['5.10.2927.0']['eol_announcement']='http://support.microsoft.com/lifecycle/?p1=2488';
# 5.0 (Office 2003 Post SP2) (MS06-061) - Office 2003 is unsupported as of 4/8/2014
eol_data['msxml5.dll']['5.10.2930.0']['product_version']='5.0 (Office 2003 Post SP2)';
eol_data['msxml5.dll']['5.10.2930.0']['eol_date']='2014/04/08';
eol_data['msxml5.dll']['5.10.2930.0']['eol_announcement']='http://support.microsoft.com/lifecycle/?p1=2488';

##################################################
# 6.x                                            #
# Note : 6.x follows the support policy of the   #
#        into which it is built or onto which it #
#        is installed.                           #
##################################################
if (!isnull(eol_os_date))
{
  # 6.0
  eol_data['msxml6.dll']['6.0.3883.0']['product_version']='6.0';
  eol_data['msxml6.dll']['6.0.3883.0']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.0.3883.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 6.0 Post release (MS06-061)
  eol_data['msxml6.dll']['6.0.3888.0']['product_version']='6.0 Post release (MS06-061)';
  eol_data['msxml6.dll']['6.0.3888.0']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.0.3888.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 6.0 Post release (MS06-071)
  eol_data['msxml6.dll']['6.0.3890.0']['product_version']='6.0 Post release (MS06-071)';
  eol_data['msxml6.dll']['6.0.3890.0']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.0.3890.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 6.0 SP1
  eol_data['msxml6.dll']['6.10.1129.0']['product_version']='6.0 SP1';
  eol_data['msxml6.dll']['6.10.1129.0']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.10.1129.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 6.0 Post SP1 (MS07-042)
  eol_data['msxml6.dll']['6.10.1200.0']['product_version']='6.0 Post SP1 (MS07-042)';
  eol_data['msxml6.dll']['6.10.1200.0']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.10.1200.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 6.0 Post SP2 (MS08-069)
  eol_data['msxml6.dll']['6.20.1099.0']['product_version']='6.0 Post SP2 (MS08-069)';
  eol_data['msxml6.dll']['6.20.1099.0']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.20.1099.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 6.0 Post SP2 (KB973687)
  eol_data['msxml6.dll']['6.20.5002.0']['product_version']='6.0 Post SP2 (KB973687)';
  eol_data['msxml6.dll']['6.20.5002.0']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.20.5002.0']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
  # 6.0 SP3
  eol_data['msxml6.dll']['6.30.7600.16385']['product_version']='6.0 SP3';
  eol_data['msxml6.dll']['6.30.7600.16385']['eol_date']= eol_os_date;
  eol_data['msxml6.dll']['6.30.7600.16385']['eol_announcement']='https://support.microsoft.com/en-us/kb/269238';
}


function check_msxml_in_dir(dir, win2k3x64)
{
  local_var retx, path, dirpat, dirpats, ver, version, listed_ver;
  local_var paths, info, lcpath, cmp_result;
  local_var this_dll_eol_data, previous_dll_eol_data, dll, reportable_dll_eol_data;
  local_var kb_name, fh, file;

  paths = make_list();
  info = '';
  if (isnull(dir)) return '';

  dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:dir, replace:"\1\msxml*dll");
  dirpats = make_list(dirpat);

  if (win2k3x64)
  {
    dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:dir, replace:"\1\Wmsxml3.dll");
    dirpats = make_list(dirpats, dirpat);
  }

  foreach dirpat (dirpats)
  {
    retx = FindFirstFile(pattern:dirpat);
    while (!isnull(retx[1]))
    {
      version = NULL;
      reportable_dll_eol_data = make_array();
      if (retx[1] != '.' && retx[1] != '..')
      {
        path = dir + '\\' + retx[1];
        file = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:path, replace:"\1");
        lcpath = tolower(path);
        if (!paths[lcpath])
        {
          paths[lcpath] = path;

          # Get the file version
          # First check if the file version is already in the KB
          kb_name = "SMB/FileVersions/"+tolower(str_replace(string:dir, find:'\\', replace:"/"))+"/"+retx[1];
          version = get_kb_item(kb_name);
          if (isnull(version))
          {
            fh = CreateFile(
              file:file,
              desired_access:GENERIC_READ,
              file_attributes:FILE_ATTRIBUTE_NORMAL,
              share_mode:FILE_SHARE_READ,
              create_disposition:OPEN_EXISTING
            );
            if (!isnull(fh))
            {
              ver = GetFileVersion(handle:fh);
              if (!isnull(ver)) version = join(ver, sep:'.');
              CloseFile(handle:fh);
            }
          }

          if (!isnull(version))
          {
            this_dll_eol_data = NULL;
            previous_dll_eol_data = NULL;

            dll = tolower(retx[1]);
            # Check if we're aware of this file name
            if (!isnull(eol_data[dll]))
              this_dll_eol_data = eol_data[dll];
            else continue;

            foreach listed_ver (sort(keys(this_dll_eol_data)))
            {
              reportable_dll_eol_data = NULL;
              cmp_result = ver_compare(ver:version, fix:listed_ver, strict:FALSE);

              # Exact match and there is no supported-range present
              if (
                cmp_result == 0 &&
                !isnull(this_dll_eol_data[listed_ver]['eol_date']) &&
                !isnull(this_dll_eol_data[listed_ver]['eol_announcement'])
              )
              {
                reportable_dll_eol_data = this_dll_eol_data[listed_ver];
              }
              else if (cmp_result < 0)
              {
                # Check if the file version is earlier than any known
                # version of its kind and report on it
                if (isnull(previous_dll_eol_data))
                  reportable_dll_eol_data = this_dll_eol_data[listed_ver];
                else
                {
                  # Check if the file version is inside a supported range
                  # and do not report on it
                  if (isnull(previous_dll_eol_data['eol_date']) &&
                      isnull(previous_dll_eol_data['eol_announcement'])
                    ) continue;

                  # Otherwise report on it
                  reportable_dll_eol_data = this_dll_eol_data[listed_ver];
                }
              }
              else previous_dll_eol_data = this_dll_eol_data[listed_ver];
            }
          }
        }
        if (max_index(keys(reportable_dll_eol_data)) > 0)
        {
          if (!isnull(eol_os_date) && reportable_dll_eol_data['product_version'] =~ "^[36]\.")
            currently_supported_versions = 
              "Upgrade to a supported version of Windows (Vista / 2008 or later).";

          set_kb_item(name:'SMB/msxml/'+dll+'/'+version+'/Unsupported', value:TRUE);
          info +=
            '\n    Path               : ' + path +
            '\n    File version       : ' + version +
            '\n    XML Core version   : ' + reportable_dll_eol_data['product_version'] +
            '\n    EOL date           : ' + reportable_dll_eol_data['eol_date'] +
            '\n    EOL announcement   : ' + reportable_dll_eol_data['eol_announcement'] +
            '\n    Supported versions : ' + currently_supported_versions + '\n';

            register_unsupported_product(product_name:"Microsoft XML Core Services", version:version,
                                         cpe_base:"microsoft:xml_core_services");
        }
      }
      retx = FindNextFile(handle:retx);
    }
  }
  return info;
}

# Connect to the appropriate share
port      = kb_smb_transport();
login     = kb_smb_login();
pass      = kb_smb_password();
domain    = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

system_root = hotfix_get_systemroot();
if (isnull(system_root))
{
  NetUseDel();
  audit(AUDIT_PATH_NOT_DETERMINED, 'system root');
}
# Search in system32 and SysWOW64 for msxml*.dll
if (arch == "x64")
  potential_dirs = make_list(system_root+"\system32", system_root+"\SysWOW64");
else
  potential_dirs = make_list(system_root+"\system32");
hcf_init = TRUE;

# Gather potential 'Common Files/Microsoft Shared/OFFICE*' directories
# These may or may not contain msxml*.dll files. Also note, some non-
# Office products will install these DLLs into these directories.
path = hotfix_get_commonfilesdir();
if (!isnull(path)) dirs = make_list(path + "\Microsoft Shared");
else dirs = make_list();

if (arch == "x64")
{
  path = hotfix_get_programfilesdirx86();
  if (!isnull(path))
  {
    path += "\Microsoft Shared";
    dirs = make_list(dirs, path);
  }
}

if (empty(dirs))
{
  NetUseDel();
  audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
}

errors = make_list();
lastshare = '';
foreach dir (dirs)
{
  dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Office*", string:dir);
  share = hotfix_path2share(path:dir);

  # If the share is different from the last share, open
  # a new connection
  if (share != lastshare)
  {
    lastshare = share;
    NetUseDel(close:FALSE);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
     errors = make_list(errors, 'Failed to connect to share \''+share+'\'.');
     continue;
    }
  }

  # Make sure we have an open connection
  if (rc == 1)
  {
    retx = FindFirstFile(pattern:dirpat);
    while (!isnull(retx[1]))
    {
      if (retx[1] != "." && retx[1] != "..")
      {
        path = dir + '\\' + retx[1];
        lcpath = tolower(path);
        if (!potential_dirs[lcpath]) potential_dirs[lcpath] = path;
      }
      retx = FindNextFile(handle:retx);
    }
  }
}
NetUseDel(close:FALSE);

# Find the msxml*.dll files potentially existing
# in the directories identified
info = '';
lastshare = '';
foreach potential (make_list(potential_dirs))
{
  share = hotfix_path2share(path:potential);

  # If the share is different from the last share, open
  # a new connection
  if (share != lastshare)
  {
    lastshare = share;
    NetUseDel(close:FALSE);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      errors = make_list(errors, 'Failed to connect to share \''+share+'\'.');
      continue;
    }
  }
  # Make sure we have an open connection
  if (rc == 1)
    info += check_msxml_in_dir(dir:potential, win2k3x64:win2k3x64);
}
hotfix_check_fversion_end();

if (info)
{
  if (report_verbosity > 0)
  {
    security_hole(port:port, extra:info);
  }
  else security_hole(port);

  if (max_index(errors)) exit(1, 'The results may be incomplete because of one or more errors verifying installs.');
  else exit(0);

}
if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else
  audit(AUDIT_NOT_DETECT, "An unsupported version of XML Core Services");
