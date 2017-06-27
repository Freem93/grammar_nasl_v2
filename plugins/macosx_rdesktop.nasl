#TRUSTED 3d203c91adb126bada68644969a911641799901fd5fd13b77eddbeddef28a0162c9f55ba582655cf202536c3bf72c6b5f8f8e7fd8ac40b6c87bbf2f1da5bf1e3493b9e1da28c72bbb8688cc9118e842f4e79461dd51c2836ddda02c077604c2312620c4421be5b5b39ba11e0869897ec97dd5d73abfcac1f2404d74bc116fbb87e6df8a8a4701c72a3613a46eb5b5faaf0ff2cd8dd71504549305f879864a6a058e863cff7a60ebc16388cb80d9dab9dd002b7167f29fc5aae37020b6b6ebde0fc7f4a0a877fbc80f75b22e741aaacfd12da474c872ff9b1f5c22f6a1b808983e5456fdbe88d1cf83281f85a253b1ca876262eac501f573e85b8287ddde7e1c87e6d149ff6b96d3f3e03adf406eaed93bbf7af9fcc53ed9dfa99f8a5359a08026c9e9e55a9c1d8144da23b1d674d7055b8c2786fc7a52ca502a58f4766264b43392992e057a1e37b7af908f8a507bf5721a08bcd0f81712554e907dbfb46cbeb07661ce0e00340bd39dcb6a83bc05e71b7e5e416ab1e86e0132741360db8c87008b0a7834f79385c88c660bd0be34b1f9528527951dee664476f8d388b1b398bdd0a72a4ce4f5fe0ff5179f192817680c5190270e0d94d7db4cb50cba475ac5c7a5fc1807d388e14787370a5c45fbfc1d95e9b5ad7e4922e83ecf3de4b771f1cf38dc016500bb3a6557fdb4af7005f8c94716c1d936fb216a834e7ee01b1c5a0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40563);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id("CVE-2009-1133", "CVE-2009-1929");
 script_bugtraq_id(35971, 35973);
 script_osvdb_id(56911, 56912);
 script_xref(name:"IAVA", value:"2009-A-0071");
 script_xref(name:"MSFT", value:"MS09-044");

 script_name(english:"MS09-044: Vulnerabilities in Remote Desktop Connection Could Allow Remote Code Execution (Mac OS X)");
 script_summary(english:"Check for Remote Desktop Connection for Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Remote Desktop Connection.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop client that
contains several vulnerabilities that may allow an attacker to execute
arbitrary code on the remote host.

To exploit these vulnerabilities, an attacker would need to trick a
user of the remote host into connecting to a rogue RDP server.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-044");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Remote Desktop Client for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:remote_desktop_client");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");

 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  file    = GetBundleVersionCmd(file:"Remote Desktop Connection.app", path:"/Applications");
  file    = ereg_replace(pattern:"version\.plist", replace:"Info.plist", string:file);
  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:file);
   ssh_close_connection();
  }
  else
  {
  buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", file));
  }

 if ( buf =~ "^2" )
 {
  v = split(buf, sep:'.', keep:FALSE);
  if ( int(v[0]) == 2 && int(v[1]) == 0 && int(v[2]) == 0 )
	security_hole(port:0);
 }
}
