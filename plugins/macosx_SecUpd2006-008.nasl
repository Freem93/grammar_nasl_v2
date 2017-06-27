#TRUSTED 47045629652272ed0ec4c7899dd2d1004f60e64c5232b63144b8f0aea9309fe4c4bb800f14ef375178038caa81e4a134dec6f2f92ad525266d4ec7fa629d8f28b1b70d493d498dab33b2ffbeefa00b9e632b6acc5727ab406f28e9e2a86f8291e92214dd411e97d35d453146bf3cd298f001186e132a854d12550fdc817c63fa9c3cf8b67c3f0090e0e580d9d202abb7a3bbce3a3615c5ba603f6bc8228f1803a9b7cca6cb541cef46cc853c641ffabf2f0c56e2ccb4c92fe90b2912f45603fe4791e90d83163ef3aa442cc83fb07beaf9f546495286b368d753e8b0b69f8946cc25a79dc60c70b9a8477b2420a1f8df5c9dfaba968d50147ddbb12e08d6e6bd441da0fcbdf27c17a60184e24b5d8746ff8b153146c188da5939ac4ed61c0cfd0bb6aaccda2d6104b2e68c970df585fea09142dc55b8d042a3ef5c5d1a5f4f7c8f2b2cbebb1cdccbeaa8725ea0580ffbdc6df57f84d936d7a0500f3151c5418b2681792505f3161d72263ecc7e1e639fb1897c9bca6ed334564452c17361b84cc2900b1696fdef17f285d2a1ecd019760bf30b62e376ee342efbd3a8bdf4333c77ee52c7586215c71a51cff1b0688b89978ae40e5f1da257f2de5a0fd27a4dcf366d174344577d7a53732728fa91b00f56d775a8ae84156533d3852885b7618470708267a5cdc7ada6f8aa9ec3ae2f7c4055c51a5aeb4e698154d5b484969efc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23926);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value: "2017/05/16");

 script_cve_id("CVE-2006-5681");
 script_bugtraq_id(21672);
 script_osvdb_id(32380);

 script_name(english:"Mac OS X Security Update 2006-008");
 script_summary(english:"Check for the presence of SecUpdate 2006-008");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2006-008 applied. 

This update fixes a flaw in QuickTime that may allow a rogue website to
obtain the images rendered on the user screen.  By combining this flaw
with Quartz Composer, an attacker may be able to obtain screen shots of
the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304916");
 script_set_attribute(attribute:"solution", value:
"Install the security update 2006-008 :

http://www.apple.com/support/downloads/securityupdate2006008universal.html
http://www.apple.com/support/downloads/securityupdate2006008ppc.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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

# Look at the exact version of QuartzComposer
cmd = GetBundleVersionCmd(file:"QuartzComposer.component", path:"/System/Library/Quicktime", long:TRUE);

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

set_kb_item(name:"MacOSX/QuickTimeQuartzComposer/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 22 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 22 && int(version[1]) == 1 && int(version[2]) < 3 ) ) security_note( 0 );
