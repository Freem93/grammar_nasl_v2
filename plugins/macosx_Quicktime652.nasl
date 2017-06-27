#TRUSTED 218fa1fe280cd9eb273e819c7e56acc9fda61278dddf2f4e8be1575d8a1be240fc2e6b64159d855c58ad6d737a8c6125cf839afbe45f66da82a6630d3b2eb08bb65542ae58989daf8e8df64e72fee8ed3dea2b8f41fa43ec750848e2ff4e39201bc5293d70f7c5d46e74580bd51ea19ee2f2848501a6b89b74cb2bc9c455a1b165b929462687fb92bf27fe15c9427194b39b42bc28f2d71091e3766dc2c4907d49231f59c606d4b9d3579ba80108ca6cd8aa659de5bec44366f829e51cdb4641054e55c8984616b40f9fb9eac08f89166522af5c86276d7a22c4d21139742f39287a553aa4215e81eb61ac45f69b1b13f83ec1679f4437e7649b7867e4f7176187a979a025bdf1e657754aa264b6004fe7c7d9bae310b8b550cb35ce079b20e9eb1d962ef0b6145f8e92dc6d479daa62c436429f1295d74e1196211b1999e9ca6187cb6fa501827eb88649f3c77632918ea1347fdfa0e4a3b5ae5c10a11ee0a4f9c5d9a4d0507c00e5b4863cd37f05b9db03c5b788f2fc0989a9e0a62d45655afe9876530f60a1793bfd0f11a17b231917eef43b0de7add8ed397b31990d34a57d5c54f926aa00de52fc5b40c4211e64103593f9d804506451aa98dd6c1637025ba9b932be2b42aee7bb022523b6a170f0d2c80e6d9841434035a294b06c4e4ff8e3ad081202556e1f24e30b429c8da77e454323af1669d6591d43304f3964f7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15573);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value: "2017/05/16");

 script_cve_id("CVE-2004-0926");
 script_bugtraq_id(11322);
 script_osvdb_id(10501);
 script_xref(name:"Secunia", value:"13005");

 script_name(english:"Quicktime < 6.5.2");
 script_summary(english:"Check for Quicktime 6.5.2");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime that is
older than Quicktime 6.5.2.

The remote version of this software reportedly fails to check bounds
properly when decoding BMP images, leading to a heap overflow.

If a remote attacker can trick a user into opening a maliciously
crafted BMP file using the affected application, this issue could be
leveraged to execute arbitrary code on the affected host.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1646");
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2004/Oct/msg00001.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Quicktime 6.5.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/27");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("ssh_func.inc");
include("macosx_func.inc");

cmd = GetBundleVersionCmd(file:"QuickTimeMPEG.component", path:"/System/Library/Quicktime");

if ( islocalhost() )
 buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
else
{
 ret = ssh_open_connection();
 if ( !ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}

if ( buf !~ "^[0-9]" ) exit(0);

buf = chomp(buf);

set_kb_item(name:"MacOSX/QuickTime/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if ( int(version[0]) < 6 ||
    ( int(version[0]) == 6 && int(version[1]) < 5 ) ||
    ( int(version[0]) == 6 && int(version[1]) == 5 && int(version[2]) < 2 ) ) security_warning ( 0 );
