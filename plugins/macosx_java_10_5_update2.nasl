#TRUSTED 97374d87619969fda4a027251fba2dfd0faa8450511cc7c1e1ec8b6d7b50bd164183f22013776a5b1a7c874bf030e207ba73afea927b532f13a6fd7cbde750dc46e91e3b6fe191f4f0d9641958f3ac0288c0d0cac9d43451864e4ae2662437e12bb37ff9ba3623509bf38ba31f8b1805b6c40632f254799bd729bdf9a455defa0ebe281a92400e2b69a0207eccc2baf33f8d112c64ff58a004e2e568348ef2828ec5ac0fa2bce5c339d7ed41737d5f3ec1f2ec325ff581d8958862314f8d8dc8e319c0d1994d7291537d7dd175d6c8c3564408bb68faa1907112631a5f96c080bd4b214951f86765c7bccc888b5fc7c62a013ea3fe53bf64af440e084f445cad4233370678aea3e0e27f907e1a86e6fa6f6f8e4e4ebb2f3dce3ed6cda3cf73c61f045d06bbaa802974709fd649cbbd25d7613bf858db0962df240bb75536d5ad784865e8da49502e85013976379cf29fe5409e8a606f76c3cef006596ec67c9dc63d07a5992733efcd6a6251afa7c5b2aaea6cef35d1e0c5703c2508e635f783186759f5e02055f8b843f1c0e97801e3a7d4415e3a14228da4bad59643955ccee2bbcfa2ed380beaa04f98d9d3e96c29a82f00cac067a7883dc8d4e3707f604accedbc49e7440137f4d8546ff57a4a3525c334a6e3b35fc2d296dd3de8395c90ea585cbf3f6fae6ec2bfc8885051a7731b647c6d6ec24d07bd19cbdf907e47db
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if (description)
{
 script_id(34290);
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

 script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 2");
 script_summary(english:"Check for Java Update 2 on Mac OS X 10.5");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.5 host is running a version of Java for Mac OS X
that is missing update 2.

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to execute arbitrary
code on the remote host.

To exploit these flaws, an attacker would need to lure an attacker into
executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3179");
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00007.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 update 2");
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
# Mac OS X 10.5 only
if ( egrep(pattern:"Darwin.* 9\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 12.2.0
 if ( int(array[0]) < 12 ||
     (int(array[0]) == 12 && int(array[1]) < 2 ) )
 {
   security_hole(0);
 }
}
