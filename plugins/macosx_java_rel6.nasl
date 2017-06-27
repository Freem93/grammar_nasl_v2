#TRUSTED 29bbbc69c32ef55d27c36852e141fb53e3e149a058df60050dae941cd3a0e216ba3cf36b7559887639c20a68cbf104aa1b273ccc9fe48cc11c3e67b06510932d74fc16bc3c38d1081d1a161fb089323691ac5fd48c4d2da8cb6d99da2f9fa6035dcbe97448069f86a3406dc9c1e54ae896975882c450372d47a5be76774c1178c6017053aeeab83c57ec6e7baa06675effc8ab72d54ed6fa152fc3470af5b48a44b7b38afa3ca4a2e70e08e6ca2ba24ac3b4fbe9b3e4915cfc937fd5e79ce927c01047d719834d9830f30e785b382ad9a296ba054faa85315d0136cba5c908fe8de334c6c2c1654f376617221383d9efdc8d85b5a40b2d556dd74fb52c9257678b9429a94f6f16f4d62515815db2824aa745767da1e048646dd46dceedd6969850eadb4fa21fa145d8fe7eb40264afd8cc10f4404a7bdd6de94c16d6e6e3028f0134c69ecde574dd2aae27d7c48f81484d0fadbfca75a77d310778ffa185bf5fb3f0f5aa16ec8ebd694fb7e167f313ce4c760f4263219a7b40a2acb88c06aef6473c72af43151d3c074a7c69af689648369bf8f16dd7fd4954c4f7ba3cc308c92ba679fe7bcc0f520016bbfead3835127bfd176b9271a5d52be1ede6df62156f5d045064cad9d1431797c5d82f64b8cfed47583688e9fd0b9deb72352beb8b83a4c4353060774b2a7db800ac02b814d85de6a93fdf42e0b4e2bab5dc52063b1a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(29702);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id(
  "CVE-2006-4339",
  "CVE-2006-6731",
  "CVE-2006-6736",
  "CVE-2006-6745",
  "CVE-2007-0243",
  "CVE-2007-2435",
  "CVE-2007-2788",
  "CVE-2007-2789",
  "CVE-2007-3503",
  "CVE-2007-3504",
  "CVE-2007-3655",
  "CVE-2007-3698",
  "CVE-2007-3922",
  "CVE-2007-4381",
  "CVE-2007-5232",
  "CVE-2007-5862"
 );
 script_bugtraq_id(
  21673,
  21674,
  21675,
  22085,
  24690,
  24695,
  24832,
  24846,
  25054,
  25340,
  25918,
  26877
 );
 script_osvdb_id(
  28549,
  32357,
  32358,
  32394,
  32834,
  32931,
  32932,
  32933,
  32934,
  35483,
  36199,
  36200,
  36201,
  36202,
  36488,
  36662,
  36663,
  37755,
  37756,
  37765,
  37766,
  40740
 );
 script_xref(name:"EDB-ID", value:"30284");

 script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 6");
 script_summary(english:"Check for Java Release 6");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X that is older than release 6.

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to escalate its
privileges and to add or remove arbitrary items from the user's
KeyChain.

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307177");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 6.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
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
# Mac OS X 10.4.10, 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.(10|11)\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) <= 7 ) )
 {
  cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"SourceVersion");
  buf = exec(cmd:cmd);
  if ( strlen(buf) && int(buf) < 1120000 ) security_hole(0);
 }
}
