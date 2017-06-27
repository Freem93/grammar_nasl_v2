#TRUSTED 8b9beb24fb46d48d96015031ccd607de4695edcfab74fe6f65f7551a8bac2fd02cd03b957ba7cdb371bee1db3f6bd7ca19f77fe942ff424106b97f81a6af88f9b807d704f07282d5bb6e6684b9cdb905ca1cff24415ceaa61cc1836d68342a73ebebaf9e7ae64f5ecc36bf1dfb5cd419f1fd12d302adf1dab80c8b3d85c0939e0acfbd90b1d93f81713aaba71f74dc886e82d53b8b6ccdd2d58b35e50908d7973cd811956c48cf8cb6b0cc25d53ec056b7520c5ae9ed86960945a003c024439361216eedcdc52d77a20a6ab451acb7335ebce272d98187adda57320c931e390349ffe81f87bbe4898716e6d758f7d691598a84e63b25728b39efc764d0331531f7682992d5186aa07f2954cc0640311a724a1fc8e4b53625cf57e778f43dea2ad556449f37b071d31ed59479060af68ff496c2b06f5ebc8db330428d374cb11468286a75d9b34bf5e7064a0b50d8ea33a8e16c80d3a5980629b8841eaf65cba37589bc8c263d0f012ae4c8636de891bbeb9e4afcac6f85e882e74913a754385fc53ce42a46689f4c21c6f3424de562549b0c24cf41a5adf29e60240db79c839a045112dd53d060f789a03a62710f68e475998a856721b238ca4aa4b614f23bbe19dae9a6bba74732cb90cc46f3e1658d43d693a61e345888c62a695d90e9db058df4f23d734bcdeb968ceb5e6353f57c0582a0b94345f40dff5988dbaa7af0cf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22539);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id(
  # "CVE-2006-3435",
  "CVE-2006-3876",
  "CVE-2006-3877",
  "CVE-2006-4694",
  "CVE-2006-2387",
  "CVE-2006-3431",
  "CVE-2006-3867",
  "CVE-2006-3875",
  "CVE-2006-3647",
  # "CVE-2006-3651",
  # "CVE-2006-4534",
  "CVE-2006-4693",
  "CVE-2006-3434",
  "CVE-2006-3650",
  "CVE-2006-3864"
  # "CVE-2006-3868"
 );
 script_bugtraq_id(
  18872,
  20226,
  20322,
  20325,
  20341,
  20344,
  20345,
  20382,
  20383,
  20384,
  20391
 );
 script_osvdb_id(
  27053,
  28539,
  29259,
  29427,
  29428,
  29429,
  29440,
  29442,
  29443,
  29444,
  29445,
  29447,
  29448
 );
 script_xref(name:"MSFT", value:"MS06-058");
 script_xref(name:"MSFT", value:"MS06-059");
 script_xref(name:"MSFT", value:"MS06-060");
 script_xref(name:"MSFT", value:"MS06-062");

 script_name(english:"MS06-058 / MS06-059 / MS06-0060 / MS06-062: Vulnerabilities in Microsoft Office Allow Remote Code Execution (924163 / 924164 / 924554 / 922581) (Mac OS X)");
 script_summary(english:"Check for Office 2004 and X");

 script_set_attribute(
  attribute:"synopsis",
  value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running a version of Microsoft Office that is
affected by various flaws that may allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Word, Excel,
PowerPoint or another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-058");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-059");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-060");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-062");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2001:sr1:mac_os");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  off2004 = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
  offX    = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office X/Office");

  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   if ( buf !~ "^11" ) buf = ssh_cmd(cmd:offX);
   ssh_close_connection();
  }
  else
  {
  buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", off2004));
  if ( buf !~ "^11" )
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", offX));
  }


 if ( buf =~ "^(10\.|11\.)" )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
	  # < 10.1.8
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 8 ) ) )  security_hole(0);
	  else
          # < 11.3.0
	  if ( int(vers[0]) == 11 && int(vers[1]) < 3  ) security_hole(0);
	}
}
