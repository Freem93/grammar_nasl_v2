#TRUSTED 01572e4f8e5f7cae224ab6e8d0a082eb27d3121b68a4850336dc4c5a938aee1a12ede9046248e6f80d672496f596e08cba039cfa0003df0943bb37bad36434c9dafd53b01efe705a203429d64b3c25ef1aebd796008ad54de309f8f43ae32850e3c28f3dd44461f5ae2f04b8400b438475d701e741875d58f8f518bd47876d4d07cced3b4e508dd71f2aded2eaa1951839cacf5818b9c24407473a63f59832c68d6ffb85de220532b9276ca8b29d3c09da23f5b34794ed30cfef9fabfe68ba0daea14c03ad8a68f2d04f4229db5766b24703ec8d7379df26eeab7f76eec248d6e8a1767a9b267a41745b622e3f456ca1af489cf80890cb5ccec183ea74124ea882d4fd425ecdddd20a1c065c071adc0e08d2d294eeb4453b98d1484d2494790832b1c44f603e3414bb3a34b71f38acfe3666afd00a28a001da7ed5d661b3aab2712971e3d2521e0649f9c328c238b45077dfe161110973612efbf61b835b253a690bc12dd730e6e4601c1d892fc6792687702c2a6152a38c0ecd4e4d5435942ae6115cf0ccc0da1dcdbe94a71c2aae3721587796170cabfac1e5f50f1e546087ed278ff568587f09f7f6dea55a38ec082391fcba543894081b0cd71ca4c2803e89c2d5ccf0fbb7e932ceef8d62b51e3366221968481ba20967c8e3543e417484a4bdff070bc64fe6b44f26bd55be9cb705e0dfa2ce6c5e2a081e82300cf68e31
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18099);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value: "2017/05/16");

 script_cve_id("CVE-2005-0193");
 script_bugtraq_id(12334);
 script_osvdb_id(13158);

 script_name(english:"Mac OS X Security Update 2005-004");
 script_summary(english:"Check for Security Update 2005-004");

 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a security update.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing Security Update 2005-004.  This security
update contains security fixes for the following application :

- iSync (local privilege escalation)");
 script_set_attribute(attribute:"solution", value:"http://docs.info.apple.com/article.html?artnum=301326");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/22");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"SymbianConduit.bundle", path:"/System/Library/SyncServices", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) > 0 && int(buf) < 840200 ) security_hole(0);
}

