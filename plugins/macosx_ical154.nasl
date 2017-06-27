#TRUSTED 708c65ad81fc79fa7107c0fc1937ba1faebdf59472ce83bce288a0a45a7efe9a795c5b3210f8c76d262f0c20e5b5d361d5901a86f3cdbcb2034893237b80a3988adf23322cf920494b382d5aec060a0920dfbd47b167563c598b0c8c537670b7cf21d47b77f97769ea961505a466e1a34fc4aea4a12cd610f0b118ab0e2b8d2e373df2512458eaf7f613d72fc4b6d1ad5eed99e195193c782d3f03ff139306a2f97473f54f1373f7ff993a68d9b0036efbbf7966680d395bd3102f4b5d08d130b0fffdf9c4b8b429dbdce2e7a0fc8cbc513698b944082cbab0dbe3e2ad8a6388f25d8e0c8cc366ba181e89e7d21edac86fef6bd939f16896f83491d59a626c1c095c6c8300e00e243b86447443239a02410a2199265909bfca958a2f8b5efc2bb6515e8bf287c83cc6bbbb530c5636bffd13e5357a700c9114f39c7ad2ef28b4d599b1fc7b35a4f54637026eb973e3f6c322386b162ad165725f744d83e61e9021b01ba5d066d2a26b626c7852b329a2ec256db0ad86ba610e492741b972f3a8c337136e6b0ac88814cb29d735f9e09b4c5f4c09314ad703ee6c042c7125d7d051187382518d001a8cd23e4cf6e56e8d77ec60a065077edde0607471d84a8e89004eb8a3ba7edab6a2cfd246768d38e65a60dab8f1fe5fc3c48af26c62cb3829ce56173b098526fcedbc6a80b3f8ecc9770dc837a116c5cfd7e0c2dcf24b8624
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15786);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id("CVE-2004-1021");
 script_bugtraq_id(11728);
 script_osvdb_id(12094);
 script_xref(name:"Secunia", value:"13277");

 script_name(english:"iCal < 1.5.4");
 script_summary(english:"Check for iCal 1.5.4");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute( attribute:"description",  value:
"The remote host is running a version of iCal which is older than
version 1.5.4.  Such versions have an arbitrary command execution
vulnerability.  A remote attacker could exploit this by tricking a user
into opening or importing a new iCal calendar.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd087f47");
 script_set_attribute(attribute:"solution", value:"Upgrade to iCal 1.5.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/11/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/22");

 script_set_attribute(attribute:"plugin_type", value:"local");
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
packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


cmd = GetBundleVersionCmd(file:"iCal.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:cmd);
   ssh_close_connection();
  }
 if ( buf && ereg(pattern:"^(1\.[0-4]\.|1\.5\.[0-3]([^0-9]|$))", string:buf) ) security_warning (0);
}
