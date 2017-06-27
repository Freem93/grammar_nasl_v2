#TRUSTED 0331e904dda6280379d2256f3dd1bcaafa019b862a7c22bb5185c6497935937ae4c2c04a082443171bbad533f2f3d69b6c2bd99ac92a16c6ecb043806b3f5a7f950a29bcb11056c9bc6310c154c6fa4a5f25e1b0f40fa98f2b2bda5b0ef71865966876c9887cfb60273528da89ff7be2e554800286f7d52112ee4936065e2f2c2ae5d895042afddb06b77ce88b9920feea1a7c7a14e64811b316ba1e52901d7f4d8cb611b074dd9f715e929af82e7f8c71a2d35e187dcad05300024bab8c012bff9fc5f4967c3de66d0482b06ed85b54f96b76b488fb0b589fb755f01254157aad2c91be51b4b6f47bba13f6db94b8c59433047d23a5407e481fc3dd2f0ac2ebd8f00b65577fe268841515e491ed4f359cac2f0874168a9afca119f1e1e8d71d4563069a02b09137216fd9e188be0597c7ac26b4f691365702beaa854b51c2f157831dda6897ae09b034433bcd8f42c019aade43fc26899e6fe320a25441787183ca7ebe1cdd053e27d33da5411666a094fbd1f7ab6dc3104d14d265a4c18fb3d8c5f801e7f1927c5f8bf828c7cc6cf3c00d595e7e172c7474c19b08b69fb371526951a14e0bca9c5b0d8cd05c75bed617d7f04b1a79c29b5ee4c57fef73300867e319213f455c094a3586541afd23ea0fdb73dc94002daf4292e939905402a4360930637b77bf8265b47d2fcb0f5b6a83f59a9387107e31de9e3e1fc972006b
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(40480);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2009-2198");
  script_bugtraq_id(35926);
  script_osvdb_id(56738);

  script_name(english:"Mac OS X : GarageBand < 5.1");
  script_summary(english:"Checks the version of GarageBand");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of GarageBand that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.5 host is running a version of GarageBand
older than 5.1.  When such versions are opened, Safari's preferences
are changed from the default setting to accept cookies only for the
sites being visited to always except cookies.  This change may allow
third-parties, in particular advertisers, to track a user's browsing
activity."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Aug/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to GarageBand 5.1 or later and check that Safari's preferences
are set as desired."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "KB item 'Host/MacOSX/packages' not found.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "KB item 'Host/uname' not found.");

# Mac OS X 10.5 only.
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  cmd = GetBundleVersionCmd(file:"GarageBand.app", path:"/Applications", long:FALSE);

  if (islocalhost()) 
    version = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "Can't open an SSH connection.");
    version = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (!strlen(version)) exit(1, "Failed to get the version of GarageBand.");
  version = chomp(version);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 5.1.
  if (
    ver[0] < 5 ||
    (ver[0] == 5 && ver[1] < 1)
  )
  {
    gs_opt = get_kb_item("global_settings/report_verbosity");
    if (gs_opt && gs_opt != 'Quiet')
    {
      report = 
        '\n  Installed version : ' + version + 
        '\n  Fixed version     : 5.1\n';
      security_warning(port:0, extra:report);
    }
    else security_warning(0);
  }
  else exit(0, "The remote host is not affected since GarageBand "+version+" is installed.");
}
