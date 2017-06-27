#TRUSTED 3650dd85e3f8254824d511036f60bf4b0a77720eb28aba15156e4d7e75a047f8f86c7dc9cd759214abc99274cab8a64962107b71e008d0851a92de240613ae43eecf6d3b45bd34a6cdc408d1724e6c89a07c22c962b2616420a39298cb90dc04e04c2f0acecdc12a07ec870d2f802251dd2ea5adaa5c214f50227f44be37da19ff401e508f53d095dcd7c4f552e5dca205e8597b7e22bdf80d36c64b4d9b9df6e9dc2280406bbbe53e8eaee3c9eb6b4a46efcffcffcd657f176ca61c9c63b01dc7eeb07e01862ea6b06723104ecff9ae26a12e3dce0fbf2b4843c0a31ee30f6d3fbf88107ce44fc960cce824e6de04aa158e0fd4f4a62eaf6ed3de8f7f124003faca397bc7a7f24b86cf3ba611890ff4879bbc7f90219ea0b5ffcb00c755be12f7266875224db900dcf66ed5aad08fa4a3b179b788769eafb3d190190d169e25457e7090c472f937edc17f279151ceb0edbfa629babd71572023a907d90b470d9950c22d0c0ccf643565e1db9de915f2d96c193a947629c4a4e9a99d17073829197e42750a04829b29cb42841edec910d52437c4998feb0e9fff2f3cb5d6d8f2634c61d019808727d8f620ec67e71d9142c3b10dfd225688f2a2d0055ad8b8b4281cb9453bda6998418c4dfc6041d45885c6bdf3035d593ce3d17a2c1cf2dc453fb684ec7ec8f52e67ecc833d2f1d444b06565359ef1d7fe7b4a20ad4a1efd77
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39766);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5339",
    "CVE-2008-5340",
    "CVE-2008-5341",
    "CVE-2008-5342",
    "CVE-2008-5343",
    "CVE-2008-5344",
    "CVE-2008-5345",
    "CVE-2008-5346",
    "CVE-2008-5348",
    "CVE-2008-5349",
    "CVE-2008-5350",
    "CVE-2008-5351",
    "CVE-2008-5352",
    "CVE-2008-5353",
    "CVE-2008-5354",
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5359",
    "CVE-2008-5360",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1107"
  );
  script_bugtraq_id(32892, 34240);
  script_osvdb_id(
    50495,
    50496,
    50497,
    50499,
    50500,
    50501,
    50502,
    50503,
    50504,
    50505,
    50507,
    50508,
    50509,
    50510,
    50511,
    50512,
    50513,
    50514,
    50516,
    50517,
    53164,
    53165,
    53166,
    53169,
    53170,
    53171,
    53172,
    53174,
    53175,
    53178
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 9");
  script_summary(english:"Check for Java Release 9 on Mac OS X 10.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X older than release 9.

The remote version of this software contains several security
vulnerabilities.  A remote attacker could exploit these issues to
bypass security restrictions, disclose sensitive information, cause a
denial of service, or escalate privileges.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/Security-announce/2009/Jun/msg00004.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.4 release 9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/09");

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

  # Fixed in version 11.9.0.
  if (
    ver[0] < 11 ||
    (ver[0] == 11 && ver[1] < 9)
  ) security_hole(0);
}
