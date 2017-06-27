#TRUSTED 6cc4390793f425bc5cd82d1c880723754e5ed5ae3d1988d9aec26cc7a02367ae027ef700381a989f496b4daa3068b56c6d730f870c1aa76332328621036a3ce993e91a8d57e1b44cd04a957271614728463fbae22d15dd9127e84c75f024f529547fda17b75d168983d96db2e6d099090b94d6e49203088e9b68ec355f57bb012dfc3d985f42b7e2455ad4c39680e598d0b4bc08d5e7d62d759db3e218c478dd536ac9c0289569e9bb09ce30e0e5ad3dbd4f600054d60eb8f3082cbf5df5c00050b5c387789731ed8be8d6eea05a293e8c6dd61fa291d2ac0ba5a1fe4579e060c972aeb1986f23ad7936bc4d99dfd314aa40ae711bccc47871b098b84d9e12432d31a0114a1c79b1536238354d4883150e9bd3cb2ba26a2a30ce340937ff4f03607956da1f90eeab27b92ff2f5b9348200ccacc820d2785f5162e714d1bf028e858e5621e058b28bc4729b3d978ad842d42c6661eb8f91ab62a46d0af50e64a18da8ecbb44ab5418d0248d27ee314532f0f6cc27d32e471244bcd0c3445790dffa75152f818e6908a47bbf798325e79c16ce3927d96084ca0a458869fcf512eb38d09c8270823539bf317169884b9d13bbbab9a2c664aabb279b5322785a31d8be0f3a6eb456a38888131badcde9a7cbfa16a7dafb824807c7dc467fefca26aaf2fd53a79cc133cf2262c58f0c1593bd4ee87176fa9ecc7ddf852807483b8aba
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25173);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id(
  "CVE-2007-0035",
  "CVE-2007-0215",
  # "CVE-2007-0870",    Microsoft Office 2004 for Mac not impacted
  "CVE-2007-1202",
  "CVE-2007-1203",
  "CVE-2007-1214",
  "CVE-2007-1747"
 );
 script_bugtraq_id(23760, 23779, 23780, 23804, 23826, 23836);
 script_osvdb_id(34387, 34388, 34393, 34394, 34395, 34396);
 script_xref(name:"MSFT", value:"MS07-023");
 script_xref(name:"MSFT", value:"MS07-024");
 script_xref(name:"MSFT", value:"MS07-025");

 script_name(english:"MS07-023 / MS07-024 / MS07-025: Vulnerabilities in Microsoft Office Allow Remote Code Execution (934233 / 934232 / 934873) (Mac OS X)");
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
the remote computer and have him open it with Microsoft Word, Excel or
another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-023");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-024");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-025");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/09");

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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");

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
	  if ( (int(vers[0]) == 11 && int(vers[1]) < 3)  ||
               (int(vers[0]) == 11 && int(vers[1]) == 3 && int(vers[2]) < 5 ) ) security_hole(0);
	}
}
