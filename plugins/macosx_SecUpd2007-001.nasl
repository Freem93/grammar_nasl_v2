#TRUSTED 876d9962f77fedabc1b8ec6ba3893ae35d45197b548b29955113f25fcd6e49c26b02b679a7e657aecbc58b8fa544a6de5310a525fcc7d6d4ee9d689971b6253f5e6ee14ffb4541e05854f3326396ce3bb3eea444e5763878061cfc97370d9e8813f528ac8749ea911ca7b4e74163484662fdd1cfa4551f69424a97dbbae29709edf4fdd33a94ef799bf6d83af3881434710be8e01775c2f29c61d5dce6fc99ee048627a2955f574741d71f7f964971774c4acfe7d93dd63f5448ccba8fda12ba8dcb9d563a6769a8909d28da96dfdea62573145e7cc3eec3581a30db09a6524922d5e40fbaabaf1250c2704a22af2866c9d45c32d737d4baa5013a52d8b1e50478df277e7c334f2fab057dd0cba5f2650b5dda1bedbddd92c60e528122ea175f7d90845ddb3e1e76dd2a8b4035a6fa670c74d4fa0de8e0bc49bea780023596e87e7cfe81c850871f9d30f86e205cbf7eee4b1ba837641f6e1aaf5f8ee7a6bf6d1e917ed100a1d344740ddf04d437dcbd31012a6c9020ffb5b537e78fe09b6d5287adc135812ab36c7db28321b1834c517cc4706debebefe433741885d4f763929e729fa07bad92ca849be31a63dcbd7f3ca69bf8636e5eb5d4be99c54198e475c8e8fb4f8eea4711cb35e4b9c4f44b865f9b231f6d287971df6dc3a1ab8437e0cdfe07f73ce1132f1b5c83275cadb071d6c670c5f94d4bb143c630ee629c6e67
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24234);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2007-0015");
  script_bugtraq_id(21829);
  script_osvdb_id(31023);

  script_name(english:"Mac OS X Security Update 2007-001");
  script_summary(english:"Check for the presence of the SecUpdate 2007-001");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.3 or 10.4 which
does not have Security Update 2007-001 applied.

This update fixes a flaw in QuickTime which may allow a rogue website to
execute arbitrary code on the remote host by exploiting an overflow in
the RTSP URL handler.");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304989");
  # http://www.apple.com/support/downloads/securityupdate2007001universal.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c80700ff");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/support/downloads/securityupdate2007001panther.html");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2007-001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime 7.1.3 RTSP URI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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
 local_var buf, ret, soc;

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

# Look at the exact version of QuickTimeStreaming
cmd = GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime");
buf = exec(cmd:cmd);
set_kb_item(name:"MacOSX/QuickTimeSteaming/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 7 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 3 ) ) {
	 security_warning( 0 );
	exit(0);
}
else if ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) == 3 )
{
 cmd = _GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) < 4650200 ) security_warning(0);
}

