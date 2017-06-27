#TRUSTED 627f074d048e860849c40f4c27e7207fc009ac0e9f378d9ef9f54939cf6207f96414ab14db0774ff2e5d7910adec26e7decb465a2aae8f4e0c253fe278ab4a817d023f6b57fc768d2a6d4c85bcd5f5cf00861dd52d8be0ae6b08c35ab1a4cb7a161588ce4f148a244549d6636f1dd22d59b173a2445902815adf17f5c795d72dbd0ff8872756d657dc2972135b27d9f1067fd790f0226e78cffb5b47047155485d58f3c6b8668b2658e627fae5c37f3ca541942d8a1ca815c2d1bf09836092fba7ca4cdc4c4ab6123f4555ff27f59840bafee41d904f1e6b83cca050b6b1490901ea821c5493ad9f867492098b2cdf99efe15cdcdf2197a07d209361fc44649c8882ac410730eb2126566dc83ccb421dffe1fd1ac41705c3ba968568e7e400cc43072a733ff28ad0fa6dcf9c5be541ab917dcf248eb73f27100359d250cab0d7cf43df369589fd763f0df54d71cc6c11c499e3d6df404c85ba8b47f6c2dd324964df126b051986e0e346e6c31e0a151580dfe837bcb10588a8486f14a24c80015374328974b68034e6303457cef61b8657a9cde092f5a8571e9c9e676899f6c2c6b592534f481e1abd034a95c637a17dae3885ee87ecd887612d30858bda51fefed1883e5d9c9038367365a255ef11051d1a116a8d4edf9504548cfd96a2bf8247cc6ca161c7699913bb4e362b73d00ed38197eb0768a5817e569b0576cf4469
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(34322);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id("CVE-2008-4095");
 script_bugtraq_id(31505);
 script_osvdb_id(48421);

 script_name(english:"Mac OS X : Flip4Mac < 2.2.1 Unspecified Vulnerability");
 script_summary(english:"Check for Flip4Mac on the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a vulnerability in its WMV decoder.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Flip4Mac that contains
an unspecified vulnerability in its decoder. 

Flip4Mac is an extension that lets users read '.wmv' movie files.  By
enticing a user on the remote host to read a malformed '.wmv' file, an
attacker may be able to execute arbitrary commands on the remote
system.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1935549");
 script_set_attribute(attribute:"solution", value:"Upgrade to Flip4Mac Version 2.2.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/01");
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


function _GetBundleVersionCmdInfo(file, path, label )
{
  local_var ret, suffix;
  local_var cmd;

   suffix = "/Contents/Info.plist";
   cmd    = "cat";


 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && ";
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
;
 return ret;
}


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
if ( egrep(pattern:"Darwin.* ", string:uname) )
{
 cmd = _GetBundleVersionCmdInfo(file:"Flip4Mac WMV Import.component", path:"/Library/QuickTime", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 2.2.1.11
 if ( int(array[0]) < 2 ||
     (int(array[0]) == 2 && int(array[1]) < 2 ) ||
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) < 1 ) ||
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) == 1 && int(array[3]) < 11 ) )
 {
   security_hole(0);
 }
}
