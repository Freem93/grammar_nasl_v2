#TRUSTED 9955f097524b2085df959cbc1983d9314e9eb13591f2e46d7550687376c6c0343509b17b9f16d22afcbabaf11c88580587aa1765ae324efb1024d0b08ac3e0c2bdc2b9b87a37fbb34c3edf963c1fe4e18c4faba92a11184a6055d1e93eed6768c292c837ca1e32d5e8d56c3f79f806ef8439eef2d40b63cc3975506b199410d0211ede7ff5f3d1b268ee18d5984ec5ec94207f1fd94163dd4cd2acf820e19fafa8ea17f4affd9faf6193502760a7a344ebd28b8e66be6d4e5db79204c6098de1fb5d8090cd8308513b9244cb1959ff29c2a18316e9a8d8c6401b5547dd132dba01bc76b0f1dab60a4db473955c2a2447902163f3d43ee07920147cbc3562970d76f11a7b047ebe58e40d314ec67e4f0df72e1f375fcd791439c4553af5d730384a6aca7a0c44c36f9064b3d849dfadf2c5be6a7eaa299ccfe0c33c0cb69c1f06fb52b10abe6fdf08213d39f026ebd559783c448ecabdafec150eab1bc64723b4405476a2efd83915c9fd95b8aa9402c034393f123aa31a714cf694a956670d783d6efdab82c6825c6cf7443cd103fb381ba74946e34add3b2a1c37d11571482df05d14de50bbfcd8d225fbe4cad41eed293da2f72871809210924a0022ad570b422d2bc9c76ea68c2e864cacf5b9423468d1d63b5cbc1c2d974f1372aa69698cc2357d0111e19eb6b3ae244773da1f1460ce04124cd6dcab51ff9e3c56ae687c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21724);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id("CVE-2006-0022");
 script_bugtraq_id (18382);
 script_osvdb_id(26435);
 script_xref(name:"MSFT", value:"MS06-028");

 script_name(english:"MS06-028: Vulnerability in Microsoft PowerPoint Could Allow Remote Code Execution (916768) (Mac OS X)");
 script_summary(english:"Check for PowerPoint 2004 and X");

 script_set_attribute(
  attribute:"synopsis",
  value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running a version of Microsoft PowerPoint that may
allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with PowerPoint.  A
vulnerability in the font parsing handler would then result in code
execution."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-028");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released a set of patches for PowerPoint X and 2004 for
Mac OS X."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2001:sr1:mac_os");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");

 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office X");

  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   if ( buf !~ "^11" )
    buf = ssh_cmd(cmd:offX);
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
	  # < 10.1.7
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_hole(0);
	  else
          # < 11.2.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 4 ) ) ) security_hole(0);
	}
}
