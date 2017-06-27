#TRUSTED 4b1eae1d82391c043798f1aa3b497dc979d000a9b13ec7ad46405dc8d1fb309dcf023b3a05e9c82b2644afba16bf3c54ef385bb302348ed10a31cc15e2476e97ad6a5795a03adaaef1a8e1dfbe6c07f9c047ce710b8bb229993728f2b04db31ed0e6eff7524d789811b1626b40a8b5437b40c7fffc5234a02df1d145b853c86c6e56eaa8631efa1a6f5d8639550b26b3f3d7854070d975f6fbd32e1658eea4ddb9cb6a475e71edd454b2172f537d3b42aef1fc614cbb462485c7ee6574795d2763b81f7ce8d76e8bb0b303fe572ae4e5b6e172287affca75637ef23b27f344b4cf00bb59023723389bb1fb09aeed2f47876d2ead5a95ef46758664878233edf4a19ff808b8152a4391690b1fabf115a219298ea53b141d555ccc6f87b08a6ade040216cc3dbba321ca598fd7fb0bf9acb2fe3225022b3225bffda4550d4475207a1103e199414e9d69379461747af0c5f412fefe6a322eb22e9c307eaa787e55d262ba03b857a7ca91dd7f13e8197e79f425ca371110a9678b85a5b040951e4a9598ac14c7c0ef7a3a511031d30ffaea70422640c8c0f66d5b063903173539d3d01012a76b9a64ca8b205c71be9016c8dc653ccc0b66c8617505c93393d5b9760c7497780fa3ac50a689423e72dc2ba6cbf5acc0c5d9243b05a1dfbcc4966eec74affac27f12d074f44bc1e4650b22bf509abda6ad5fc80d171d9654b31a2c57
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39435);
  script_version("1.14");
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
    "CVE-2008-5347",
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
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1106",
    "CVE-2009-1107",
    "CVE-2009-1719"
  );
  script_bugtraq_id(32620, 32892, 32608, 34240, 35381);
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
    50506,
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
    53167,
    53168,
    53169,
    53170,
    53171,
    53172,
    53174,
    53175,
    53177,
    53178,
    56457
  );
  script_xref(name:"Secunia", value:"35118");

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 4");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.5 host is running a version of Java for
Mac OS X that is missing Update 4.

The remote version of this software contains several security
vulnerabilities.  A remote attacker could exploit these issues to
bypass security restrictions, disclose sensitive information, cause a
denial of service, or escalate privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/Security-announce/2009/Jun/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.5 Update 4 (JavaVM Framework 12.3.0)
or later."
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/17");

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
  local_var buf, ret;

  if (islocalhost())
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");


# Mac OS X 10.5 only.
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
  if (!strlen(version)) exit(1, "Failed to get version info from '"+plist+"'.");

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 12.3.0
  if (
    ver[0] < 12 ||
    (ver[0] == 12 && ver[1] < 3)
  )
  {
    gs_opt = get_kb_item("global_settings/report_verbosity");
    if (gs_opt && gs_opt != 'Quiet')
    {
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.3.0\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
  }
  else exit(0, "The remote host is not affected since JavaVM Framework " + version + " is installed.");
}

