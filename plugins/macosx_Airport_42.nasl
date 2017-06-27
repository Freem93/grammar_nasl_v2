#TRUSTED 2c1defa7c97d0685f628a423f9185f1a6e9ce655c55a424b4c3a11444e595b0781c90942fcbd3dd644ae90d5361ca93636b9e148976a85dab6d335b6bf30317ad7840d720e36c424476fd305ff1004ef8a354f44591004fd87a4306099bb84ebd8da158d8f8f0b5258cecf103360bf49e60b3dfb58f5daedb9bacbbb2ac8bc39fb5979ea81db772231d49e3490b491d411dccc44b892f36a8242580410a2a77a304a8870b9337287de695b6f014c556d8b2367032188149c89c96b3b9208b983204aa77ec163e5262e11074f29ec69704720e18a86c368a47b62068f8a4c33bea6ab4d3ea541f83cfed04732b91cafbd1e49c3e0b427314e4120bfa33f9164672e27a63eec315456e490ca4fb962897e1d2313c13242c6e51c7c8e61f878869737fa941b31db3ca99d0daa21de260b5a73b7191fee4552ad496fe9f3d3853c139746d5cb7d088a2c61d261be8e1e1e6eb56dfac360b77f4a0720764389f6f8862179fc14407b24e1c67e99dd24b6363b086bff549093f98bfbc7a6ebaadd8b1fac24ff8f606080e1319978da7e6473667b837d7e65ad2917c02d06c05de3a0c49157851ac4ee045a12cce97e11812dfa005bbb91e9eebc75333cea00a495d87232700bacc09bde1d4945eda10586076d3df62bd3a8f7b4dea7a9c933081c17e3e2d955360347fae62ad5dad31b6bf4ebc8c607b1bd21ce882a456cdf3964bbcf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19295);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value: "2017/05/16");

 script_cve_id("CVE-2005-2196");
 script_bugtraq_id(14321);
 script_osvdb_id(18085);

 script_name(english:"Airport < 4.2");
 script_summary(english:"Check for the version of Mac OS X");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X which contains an
Airport driver with an automatic network association vulnerability, that
may cause a computer to connect to potentially malicious networks
without notifying the end-user.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA23400");
 script_set_attribute(attribute:"solution", value:"Upgrade to Airport 4.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/25");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) exit(0);

cmd = GetBundleVersionCmd(file:"AirPort Admin Utility.app", path:"/Applications/Utilities");

if ( !ereg(pattern:"Mac OS X 10\.(3|4\.[012]([^0-9]|$))", string:os) ) exit(0);

if ( islocalhost() )
{
 buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
}
else
{
 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}


if ( buf && ereg(pattern:"^([0-3]\.|4\.[01](\..*)?)", string:buf) ) security_warning(0);
