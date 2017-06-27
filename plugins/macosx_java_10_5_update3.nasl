#TRUSTED 4309eb9ea93523d3f59968993d3ca389a4d7b904f33cbfca9b9a1ab0d01854c35c0985eb9cfa03134a2eb9258366ca1e5a8d7f51808afddba8272d04625529504a7df9ba38b86c9b82cecd291b7bdf99b2472d92c68649c551af5768e8bd73c9e072e05ab76db50e6d6f3993a40e3179a48fbda5dff3bbce0df88c8f60dd45c8e61c51382e835fd9c53a2b205cabe162dbbd3bb6b361f92777d1b089dd23d83d697989b0cc37f1c32ca8c06be20092a9ae66d9482250d6db750f8c419b378d6a934a7c09af9f902f10143f9c3793055dbfae709f8dd005a4e50e85077a11e3e7a15f6915585f8e0844ef88e8d263133d1d6040a2a4c636525692265cbc5b4655be6defe9c15c5a7b42e19859da4ac056ef217b2e2066f04579b1c9e77adb1af6ca6b5d32b846090a6c0aafab7b43906d4b1f74cca3bfa77dbf0c6efe53490c8b60e6175850481680571d3752fed12a7b22b3be463ed2f839ac034d32ff5f0040774e62de9294a098ead3b1feb4e72510169c3b656c962e50da308b58b152791e2a77a0dabdf26eee0f5a6c189da3820ea70bcf06c1dc201ea11d51ac652cab7e1c1bae0dbed80e8b79aed47584036283fd39d506af332bf2d70fb1faa6ed81a0fe239c44569ed36da59f2c9183e64e5e9c1033e45ddfd907b582b5abecd945eaea762d6280d44cd91ad877cb96a4e501d68c56cd2962b52a249cc1d971837e42
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(35686);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 3");
  script_summary(english:"Checks for Java Update 3 on Mac OS X 10.5");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:"
The remote Mac OS X 10.5 host is running a version of Java for Mac OS X
that is missing Update 3. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted Java
applets to obtain elevated privileges.  If an attacker can lure a user
on the affected host into visiting a specially crafted web page with a
malicious Java applet, he could leverage these issues to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3437");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Feb/msg00003.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 Update 3.");
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


# Mac OS X 10.5 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 9\.", string:uname))
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

  # Fixed in version 12.2.2.
  if (
    ver[0] < 12 ||
    (
      ver[0] == 12 &&
      (
        ver[1] < 2 ||
        (ver[1] == 2 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
