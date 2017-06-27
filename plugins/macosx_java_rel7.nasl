#TRUSTED 2d5be669cb8a67b867646b369dae4e6d10fa544032c243d9c9eb0c985af05d62dd2a315cc151082378ca51a727ed45daf28c4983ea6b200ca88cce9d749f0bdb2c7f57e6d7e333d5c3b6bf775b20d8a2b2f331978dda31c10fa3da34fcafa2479c8e1b0b6d08af50fd5481a4a6ef5713911046135fee320c6208d13aff61760575f98d6aa1c6d2a5b0f43c95631ca2ba175ad4f632bf5f78eaa8d7a4460e98854e80888b1a1727a988eedd917e88053c7b4cae64a527faa718cc43ce677e7d5acf93f4fc890009dc1ee4184f56a30447139e9f3c9582c0d30678aa642d5568ae39c5ac5582017759b176eed86e512bc8adede58a4e6bd610e1c18496f932e20036ce18c4f199977728a496339554ae3dba13c53251dc1471218019a68ab28b1769c7ffcbd05e1453156ca94d9973da36ec2b5fa8587ff58c722eaf3298fd8403cd6f2d3c8f12a4bf644644fa5cb9aedfe877d3bb9f2b6ea0107e671ad21487da1329e35bad1dfe39c9dcff41d4485fe5814ebbda28cf2a999a863a357a70e655f5d7581e981a465bb90c69e79b3ff37e1b06f9218db740e1de29ba2600880f3918e0660221bf5f2c732d9bae039a52cd9a2c01447eecb1241e1082719a76534794e02e67d4caaf7e4265b1b35f0a683b3afb34f854b5bf4b36bbfc1c25b9847af28e7493a2bef18157804cfaed6bd64b0ca3ba3273b3c5b7d0be76f161557fea
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34291);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id(
  "CVE-2008-1185",
  "CVE-2008-1186",
  "CVE-2008-1187",
  "CVE-2008-1188",
  "CVE-2008-1189",
  "CVE-2008-1190",
  "CVE-2008-1191",
  "CVE-2008-1192",
  "CVE-2008-1193",
  "CVE-2008-1194",
  "CVE-2008-1195",
  "CVE-2008-1196",
  "CVE-2008-3103",
  "CVE-2008-3104",
  "CVE-2008-3105",
  "CVE-2008-3106",
  "CVE-2008-3107",
  "CVE-2008-3108",
  "CVE-2008-3109",
  "CVE-2008-3110",
  "CVE-2008-3111",
  "CVE-2008-3112",
  "CVE-2008-3113",
  "CVE-2008-3114",
  "CVE-2008-3115",
  "CVE-2008-3637",
  "CVE-2008-3638"
 );
 script_bugtraq_id(28125, 30144, 30146, 31379, 31380);
 script_osvdb_id(
  42589,
  42590,
  42591,
  42592,
  42593,
  42594,
  42595,
  42596,
  42597,
  42598,
  42599,
  42600,
  42601,
  42602,
  46955,
  46956,
  46957,
  46958,
  46959,
  46960,
  46961,
  46962,
  46963,
  46964,
  46965,
  46966,
  46967,
  49091,
  49092
 );

 script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 7");
 script_summary(english:"Check for Java Release 7 on Mac OS X 10.4");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS X
that is older than release 7.

The remote version of this software contains several security
vulnerabilities which may allow a rogue java applet to execute arbitrary
code on the remote host.

To exploit these flaws, an attacker would need to lure an attacker into
executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3178");
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00008.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(264);

 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/25");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");

function exec(cmd)
{
 local_var ret, buf;

 if ( islocalhost() )
  buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
 else
 {
  ret = ssh_open_connection();
  if ( ! ret ) exit(0);
  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();
 }

 if ( buf !~ "^[0-9]" ) exit(0);

 buf = chomp(buf);
 return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# Mac OS X 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.11\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 11.8.0
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) < 8 ) )
 {
   security_hole(0);
 }
}
