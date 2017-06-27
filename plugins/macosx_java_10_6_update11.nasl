#TRUSTED 3c6cdb168e4f238b2248f82e48328ee252695bd6093aa43270c6e7f5a4d073be07d52af1757c0dd31c9d1d833ad0900dd44b865d368c293c9bcb50c01db50848fa59948e976a9ca4e898956745d4d31b1c6856dd37d5f31b36afc861400c249c4aa9acd7a1aa9c7057d6273b9874bc3ec019cc5c0263038a2133da788f2d149b9f84b71760cd3891ea841a9caa4c24962ecbe3dd5e3b82e657e3c273de1b1253c061bfdbd636deedbc08f5cb30e3c58153c04d792769b14f65fc401cddf33ab7e950b2a27188d6043ae5bd5a834472d86cb1b241585d18b0b834d5a05188cb82fb9f28940927628554209dd6a41ed87a5d7ef3f45f2ec9326bd30799b156724a6df853f6d42adcb99125480efe13b92ddfda56998f419905e3a4fd37905f664b9fe107534c6fa6db7d07744b23aec16e58251085bf7a8ce627c72a16725e61f32096c98e79a8e57e551e2362df2cfdcc045c298fac5c157756b7e191fa4aa64ecc86e1790bc2828a4c76ee7cb62325344c9f520083cc2455fc60b6377d84ba37fc5fe65d0130991f55f3d9c51c8c6cdef6ed9e26b7d9ab34d5841d68b7885ee3aa039cece5f75d00d91bbacde974cfd2317319ff0d9ffc9c745922d1c1a39c86cd713db579d701909de374b4fe9bee36e5e8b19f5e1c9a3e6081151b2f7d92687b5978c55f6ff42ec1ccf22a7c237de010bf4e65e3c53562b8b8023759ec726d
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62594);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/03");

  script_cve_id(
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3216",
    "CVE-2012-4416",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5075",
    "CVE-2012-5077",
    "CVE-2012-5079",
    "CVE-2012-5081",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5086",
    "CVE-2012-5089"
  );
  script_bugtraq_id(
    55501,
    56025,
    56033,
    56039,
    56046,
    56051,
    56055,
    56058,
    56059,
    56061,
    56063,
    56065,
    56071,
    56072,
    56075,
    56076,
    56080,
    56081,
    56083
  );
  script_osvdb_id(
    86344,
    86345,
    86346,
    86348,
    86349,
    86351,
    86354,
    86355,
    86357,
    86358,
    86359,
    86361,
    86362,
    86365,
    86366,
    86367,
    86368,
    86369,
    86371,
    86372
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-10-16-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 11");
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
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 11, which updates the Java version to 1.6.0_37.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5549");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Oct/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Oct/88");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 11, which includes version
13.8.5 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Double Quote Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os)) 
  audit(AUDIT_OS_NOT, "Mac OS X 10.6");


plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = 
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "13.8.5";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
