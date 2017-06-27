#TRUSTED 3829eb7726976a5afa41069dbfbe0172e09455ec790d5ba4a27705f32ebe3a69bafa45e5bb77f4f7b75e6353b7ead31e49a84f00a95d4a10f8b0723eb88822ba2a6187ae3e9bdfb906897a3e8058fc1a2428bc1b43e4a307b04b898fade7fa158cfb6d0f0b4d0d8cdba5df4d5160a9c5997503c8188528ce9745ae8fdb6b003acb1b8c14d35d2138831021386601299c55067162dc79a15f6041db4b99ef1e70c94fb5b46afad57e1de4438c7d3442e3b4298095e0001574e756f1150b0d966c24d2cc6624c06ca5c989f5de9fff94b3e67e3b0b29890143fdd0c91c51bda8e86394de905be246874b2a07c29ee4b6d378f6f3c237f0ecbe2a6225daed07983063e5ab36b9f9ae4d53f17c60b801d4b51db567789e95e33155fd28448cd3a50979d26427f9c8c52e1a76871dfe21c889ee0728a42416c050b69a11ab441d15717c01ab8c733f32db95a369035dfbf6636418690d2ddbeb1bfa7b0e72cd32658685867d5e95b80a4ccb3368e298e8a47ed3ba4731515e4156f2712d89be86703d3326cb56e1d994a23f48760d56797e23a76f89f10b58544b84e0eaf655fd41dda220c308c10a43dc6225e478a6f97b40214c8195965beef40db0b2e36f41340b0f0510a9f4cc172a499e092800d2bb96488214af7ce9758743f0d549c28da3291ec99d1d2f6e1be305a3783abd55440950914a46316d50a776a67cc59307f3ab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24328);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id(
  "CVE-2006-3877",
  "CVE-2006-5994",
  "CVE-2006-6456",
  "CVE-2006-6561",
  "CVE-2007-0208",
  "CVE-2007-0209",
  "CVE-2007-0515",
  "CVE-2007-0671"
 );
 script_bugtraq_id(20325, 21451, 21518, 21589, 22225, 22383, 22477, 22482);
 script_osvdb_id(29448, 30824, 30825, 31900, 31901, 33270, 34385, 34386);
 script_xref(name:"MSFT", value:"MS07-014");
 script_xref(name:"MSFT", value:"MS07-015");

 script_name(english:"MS07-014 / MS07-015: Vulnerabilities in Microsoft Word and Office Could Allow Remote Code Execution (929434 / 932554) (Mac OS X)");
 script_summary(english:"Checks version of Word 2004");

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
the remote computer and have it open it with Microsoft Word or another
Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-014");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-015");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Word", path:"/Applications/Microsoft Office 2004");
  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   ssh_close_connection();
  }
  else
  buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", off2004));


 if ( buf =~ "^11\." )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
          # < 11.3.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 3  || ( int(vers[1]) == 3 && int(vers[2]) < 4 ) ) ) security_hole(0);
	}
}
