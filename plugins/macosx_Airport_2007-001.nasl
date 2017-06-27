#TRUSTED 9b28eb45ede9ed26562323463b2e0318e4e867b8889e14af60c9d145318c4a47c71a328b3cca14ea3d8e382a15ba28562f2ff52538af5aeff5c596c3263b01c43f43796ca178a8d74341f33a42addc56535212e7de7ac7e17eb14e5b7e07494b5475aee6b76019700424f54079c969ee4381596dc2621f2089651ed9079eb2cca39d5ee1de5a6ea274d5b451e8e1a3530c3edb3a77425c0660be554c8afbd69d5562f64a2c9b04e01fdc2228212225f1042d36e88ceaf404f48896ef7f6b61766efd33a9e3542d7a886f5bc0b3e987f9a057539f5c4c0e6ed1cbc586a98e7e7edd39e440a008cca9a090cd426ceaf219d084c06eb1a165e6b7bff9129f7f59c124ad8e356ece59740ff0ba3caaf7dfa1b192728d6c7825785a24fbcbed72725e6a42ad77ba794e3f5a2acb94dae53b5dc0962f80472a9000ef83c3ace2cce86848cbfe7ee1d0719ca1b630cd8124bc93baa80cf58439dfbb59ee844e778c9efa4c0cedf396de94a6d95489e6684549fddb695abe067452168988e1eaf790ec729f523db01361f7cb4450d76bb8fbd7f184ce6f7a5c01828f409b4dafe103f4141c72fbdd1f8a164fac2936d841693092cb510facd9fe6ba6cb4b808fec3bfe4bd0faa26225c8d09cc0cfb453c50b8ba9450391aea865c95e0ff3fdfb7c6947803e035ebf911833068dee1c1134e7817dbd924159fa8a541247c25ac883480b22
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24241);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value: "2017/05/16");

 script_cve_id("CVE-2006-6292");
 script_bugtraq_id(21383);
 script_osvdb_id(30724);

 script_name(english:"Mac OS X Airport Update 2007-001");
 script_summary(english:"Check for the presence of the SecUpdate 2007-001");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not have
Airport Update 2007-001 applied.

This update fixes a flaw in the wireless drivers that may allow an
attacker to crash a host by sending a malformed frame.");
 script_set_attribute(attribute:"solution", value:
"Install Airport Update 2007-001 :

http://www.nessus.org/u?0af16cb0");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305031");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/30");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/01/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");

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


 buf = chomp(buf);
 return buf;
}

uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);
if ( ! egrep(pattern:"Darwin.* (8\.)", string:uname) ) exit(0);

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
if (
  "AirPortExtremeUpdate2007001.pkg" >< packages ||
  "AirPortExtremeUpdate2007002.pkg" >< packages ||
  "AirPortExtremeUpdate2007003.pkg" >< packages ||
  "AirPortExtremeUpdate2007004.pkg" >< packages ||
  "AirPortExtremeUpdate200800" >< packages
) exit(0);

buf = exec(cmd:"system_profiler SPHardwareDataType");
if ( ! buf )exit(0);
if ("Intel Core Duo" >!< buf ) exit(0); # Only Core [1] Duo affected


cmd = _GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && buf =~ "^[0-9]" && int(buf) < 2214600 ) { security_warning(0); exit(0); }

cmd = _GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && buf =~ "^[0-9]" && int(buf) < 2217601 ) { security_warning(0); exit(0); }
