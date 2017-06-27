#TRUSTED 56ef99686160c0fbdaf608af405aa37b123a30c82ca5c5630927b3ee3a60e70e71a121c493167cfb4ddfdb92eda8d4e6ed88257f2f1762bd3784790462e2f77bb70131b115301f57e2676ef342f75eb08d6af24427999ae10a4cea19fc615d4acada96fa2afc1557721a792c08fa54166a9af378616c76677cd0e4c15e9691cfce5e224a4d15db5402178d4bf41e3d38475e0b5fec476b4a3811c6b3a69f7d43ed51a405083a5a3b22a8cf507fcfaf5f2c0f13aeca6fad009471720a8f121b7d1674d279f30bdd4f57122e1ccc55c4766fbf8b8d737ee130a1aa11e97b6034a7a4d119343c23a103559da1f8cb23e074a5bfcf8c70fb342c8c7cb11e3ff8e630b9d2177d23e048101257e6f6f186891d48f56163a61c165f582c34ad0aba2ec6c75657f0891ff9e26bee133543ba50bbcb8fce85e3faa4d168da8ab550f4abc9d90a847717829c8b2d41fe4c47cf9a89e21187334bf78b4ca5d5c03bf34edd1d246e99b4e2fbf8d9877b1c08740f3c3b5947483b0d8bb119627728cd7ab2fab2f7251009e527508079654224370477cad7b623957239f5585b8f406a33ab442ac8821a13ba8ec1a7c08bd480df235c3b3f5f2fbace2e48343a267288552809120e7a8cfbfb5dcfd8463eb294cdca494a7a0fd0997c9660de2ce0855227b46004e860eb62d7d55ba0d5ee771220b277156ef982558fb79da278cb61d357568e7b
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");

if (description)
{
  script_id(35685);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5340",
    "CVE-2008-5342",
    "CVE-2008-5343"
  );
  script_bugtraq_id(32892);
  script_osvdb_id(50509, 50510, 50512, 50514);

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 8");
  script_summary(english:"Check for Java Release 8 on Mac OS X 10.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS X
older than release 8. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted Java
applets to obtain elevated privileges.  If an attacker can lure a user
on the affected host into visiting a specially crafted web page with a
malicious Java applet, he could leverage these issues to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3436");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Feb/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 8.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/13");

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


function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);


# Mac OS X 10.4.11 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 8\.11\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 11.8.2.
  if (
    ver[0] < 11 ||
    (
      ver[0] == 11 &&
      (
        ver[1] < 8 ||
        (ver[1] == 8 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
