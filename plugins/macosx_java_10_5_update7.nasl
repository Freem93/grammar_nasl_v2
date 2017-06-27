#TRUSTED 4413787bd7e8d06e8f0e892331dd6654221dd71af0064f4c2152e3b1d4d6fbc6540c676438f99b6ef59022f0062c61ba14fdb2cc25b5d30736e62311f22492b37771142a09c490dd1c796ff4504075789dfdd6c058d396e87cfb23b658f13c6efcc0b84b349bb18a1e53a3510a13d2c648aa48e09c9909376bce04faec22010224fada622feea53f47233a6be7fc02b272bc4f42a9da2020c8eceb32e3abfe18a7c419da85327649176d4e73a14b55eb67c98d8df162d26ae65b08ac412e46be69fc6cbe9bfba3b8ed6702fe6026fb4520701605eabdee3c8bd7503913b1e39c7063efc5371e41c4f67719ea52f7429ce833809ccfa1e8836463e0b7f6032b354068a84428a0ebf744240a84c75f5c2dddeef443ccd75d882ddc70bd7b8d5fde9c0d422183a83831eaa5cfeca1350284fabcb087dfbc71a24cd82c6d95f5b6ec9e87dd1494fa0284e3b45f4dab7064247999f8e44aee7692cd07bb78556e02b519a9aba52fff7da47fc0be782e05fb8001f778b67869b882533b149a31b4d3b4b6266054e417780d5559017d8ddf3731152fc3e55650d2cb1404f5c64ff4f7456b8035fd4198fade7d60ccf7edef03bfb7e940dfc4d4f7fde63b7fbaaf07deced03dd0ea8d98325cbe390983e1ae60ee6d550c30bce5f34e6f5112ed7673fd6933b35273b5cc7fa5e8b2d406124bdc1a6b2878a0dfa698627501ba115efa9624
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46673);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2009-3910",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0538",
    "CVE-2010-0539",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0886",
    "CVE-2010-0887"
  );
  script_bugtraq_id(36935, 39069, 39073, 39078, 40238, 40240);
  script_osvdb_id(
    63481,
    63482,
    63483,
    63484,
    63485,
    63486,
    63487,
    63488,
    63489,
    63490,
    63491,
    63492,
    63493,
    63495,
    63496,
    63497,
    63498,
    63500,
    63502,
    63503,
    63504,
    63505,
    63506,
    63798,
    63799,
    64866,
    64867,
    69032
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 7");
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
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 7.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/May/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

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
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.6.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 6)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.6.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
