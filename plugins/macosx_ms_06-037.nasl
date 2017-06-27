#TRUSTED 981316813b6b990390a31a397bc996c6483f5fd31939f5e290800c1fbaf895ff9264cd781af1a47d75d8b5e26ec07309e1c8a35df44f4cf21ddd5b06a2bb35ec7c78b499001fb9f69b41782797a4b99b804b4ad9f88e028916d747ea9d65fe136b3460ad5b5e96357383601cdc32f2bd40189e010dd0baa2684e417be25ae205693c367524f124b81a030b84ad7629dc31162d7f4aaaf38a48f702791ac748400a13064a8f87f65a5b4a2e4c5f1886e250121bce4154994fffdcd8c4f185febcf764b9fcfe38d4883380cd6f186c5fb7174a110f5d651c20f862a6a6b560025f0cbb32bf2af000392e97c22826a0d673111d300771f9b528628785b8b52f6f8698e3fbaef3197023d488d33fd87d19648b08cfb8f1f20c48a11c2a884fdbb4c59be26bc37d964e83bd3b3104381dc9dd82af221504cfe76a902ce7f61a90d3b1da46fb72b5c577a2d322a5978b2cde40d377200baa845762395e8be0f5ebc098c35241d9e5e70dc28ae88c83972507e609e5b94f410a8903f50bb9d4ef41a59a46cfddbd88c2a7280d1f67252a918041953fd7d7009f7289aaa065a7647066a3daae355a53970147c9a80d30a9c0e01d6a1dd1edd8d7ed1938bb4408233d79e30e40b04c1c75d337b6caab07ff0cde42cbb5d13a4ec6120c004a078541f154b4635b96279033feba2cb01d3340c2a98f2e1c81da74893b6eaf3dffe88797d671
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22025);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id(
  "CVE-2006-1301",
  "CVE-2006-1302",
  "CVE-2006-1304",
  "CVE-2006-1306",
  "CVE-2006-1308",
  "CVE-2006-1309",
  "CVE-2006-2388",
  "CVE-2006-3059",
  "CVE-2006-1316",
  "CVE-2006-1318",
  "CVE-2006-1540",
  "CVE-2006-2389"
 );
 script_bugtraq_id(
  18422,
  18853,
  18885,
  18886,
  18888,
  18889,
  18890,
  18910,
  18911,
  18912,
  18938
 );
 script_osvdb_id(
  24595,
  26527,
  27148,
  27149,
  27150,
  28532,
  28533,
  28534,
  28535,
  28536,
  28537,
  28538
 );
 script_xref(name:"MSFT", value:"MS06-037");
 script_xref(name:"MSFT", value:"MS06-038");

 script_name(english:"MS06-037 / MS06-038: Vulnerabilities in Microsoft Excel and Office Could Allow Remote Code Execution (917284 / 917285) (Mac OS X)");
 script_summary(english:"Check for Excel 2004 and X");

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
the remote computer and have it open it with Microsoft Excel or
another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-037");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-038");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office X");
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
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_warning(0);
	  else
          # < 11.2.5
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 5 ) ) ) security_warning(0);
	}
}
