#TRUSTED 459b356e2a99f77109a723510f559a42321f835df8482e6c7bed86bd9ed81335ef86a39e093c20e90af4127230264e39b23f4908edcf331b9a5ec860d5ec0403746c37b6907948ba1ef33ed5c6bbaf6642c155519214161b68edbf41a73866dacb9b6ccc96cc76aa9ebb0ad2fd514536b78444c587bf56524ff69751432645ca915e19f08dcc9bacc72d2bd755c2dc70b7003ade8e287c22f093f5fd935c49bdfe44fc972453010dafbeadddd48dd97dc2d7e48d5a0346e0eec71df8c38ccea9bb7e2e68da43bff5ce94384faf40c6f762e2f75fcd6f2f298d064b9c19e8616e7110bd438273687c2b828cb45c25b540cd61366f081e764a15138cf65c6a0e6073a459da7bab1469d937b83589427c2e6bba3a09c0f01ad97f7346e740599b0f5035be77cbedfd84e318d9ff2e0749a2c091760415b69da92d6fc660768ac2cab62ccbff67e13f7aebfd9e7744d6662078470d01691bdafa4d75316b6058089e6bb06b69e2aec1ec08b176617a23cd53e3d434882d0f4fac743f0daaf4504df88b49ec65c5b1f609d0bf8a3cf764abb7c1676ed829cb9b8919bd9be9fcb9283d7af70374a36ad5ed21becdaae2251cb83b3b5d87b39e46c1c0b2846e458d7c277f351bf238f3e272e60ae91c871ed9b5fe96c6b35ca0549a933fc56dcffaf4133b542836ab62e925248734d7c9e75b2425271a566b12ba9fbc48c6251dc218db
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22418);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value: "2017/05/16");

 script_cve_id("CVE-2006-3507", "CVE-2006-3508", "CVE-2006-3509");
 script_bugtraq_id(20144);
 script_osvdb_id(29061, 29062, 29063);

 script_name(english:"AirPort Update 2006-001 / Security Update 2006-005");
 script_summary(english:"Checks for the version of the Airport drivers");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the AirPort
Wireless card.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security update regarding the drivers of
the AirPort wireless card.

An attacker in the proximity of the target host may exploit this flaw
by sending malformed 802.11 frames to the remote host and cause a
stack overflow resulting in a crash of arbitrary code execution.");
 script_set_attribute(attribute:"solution", value:
"Apple has released a patch for this issue :

http://docs.info.apple.com/article.html?artnum=304420");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/09/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/21");

 script_set_attribute(attribute:"plugin_type", value:"local");
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

function vulnerable()
{
 security_hole( port : 0 );
 if ( ! islocalhost() ) ssh_close_connection();
 exit(0);
}

function cmd()
{
 local_var buf;
 local_var ret;

 if ( islocalhost() )
	return pread(cmd:"/bin/bash", argv:make_list("bash", "-c", _FCT_ANON_ARGS[0]));

 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:_FCT_ANON_ARGS[0]);
 ssh_close_connection();
 return buf;
}


uname = get_kb_item("Host/uname");
if ( "Darwin" >!< uname ) exit(0);


#
# Mac OS X < 10.4.7 is affected
#
if ( uname =~ "Version 8\.[0-6]\." ) vulnerable();

#
# Mac OS X < 10.3.9 is affected
#
if ( uname =~ "Version 7\.[0-8]\." ) vulnerable();



get_build   = "system_profiler SPSoftwareDataType";
has_airport = "system_profiler SPAirPortDataType";
atheros  = GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");
broadcom = GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");



build = cmd(get_build);
airport = cmd(has_airport);
if ( "Wireless Card Type: AirPort" >!< airport ) exit(0);  # No airport card installed

#
# AirPort Update 2006-001
#	-> Mac OS X 10.4.7 Build 8J2135 and 8J2135a
#
if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J2135a?", string:build) )
{
 atheros_version = cmd(atheros);
 broadcom_version = cmd(broadcom);
 if ( atheros_version =~ "^1\." )
	{
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
	}
 if ( broadcom =~ "^1\." )
	{
	 v = split(broadcom_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 4 ) vulnerable();
	}
}
#
# Mac OS X Security Update 2006-005 (Tiger)
#	-> Mac OS X 10.4.7 build 8J135
#	-> Mac OS X 10.3.9 build 7W98
#
else if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J135", string:build) ||
          egrep(pattern:"System Version: Mac OS X 10\.3\.9 ", string:build) )
{
  cmd = GetBundleVersionCmd(file:"/AppleAirPort2.kext", path:"/System/Library/Extensions");
  airport_version = cmd(cmd);
  if ( airport_version =~ "^4\. " )
  {
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 4 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
  }
}


if ( ! islocalhost() ) ssh_close_connection();
