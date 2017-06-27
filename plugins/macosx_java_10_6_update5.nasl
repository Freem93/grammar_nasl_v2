#TRUSTED 4958ad78b88926f08812c23d58346cb7d370802460a8083c25466cb9a14788bb7c55c1f2933ecbeaa4e46dbcf82d2d4b4d68cf178a539546e3da6b23754c65853da354aa5a9b4c908188964dbd7dc19cf2614e144edfd538282328e3c2524b6b3dc085d77ebc9c5ebf31f01b471b3aa81b5b9e90ea5409bd677d8bed01c09e1fbda026df1be4a1ec66c697d90eda65617f781e5d364cc768915578e46f76403b8e403d41b77a5f247ce2ef6a58cd94b062f1abc4caa2a1181e7e526bee6f982ccbb4353bc1fd713b3488f22b92a6f6867be308a938607613a8840ebeb8af0cd72941918cb1c580723d441ed4ab1deaef3399d627972bf0ef73a670e4987caf3240fd46e1a2ea25103cedf02b223e0250ef55eb87127b256bdeb110f26350b603c8e166faa568a27000d741acbc800aebfcff6963c489d8f6d440747d8e92e4c27c5e30702625bac8a0edbcf74dc40f9393ce424fddb3cd9679789c318ba4677ff1cec47e20bc03b3e75ea909f984d2077d4172d08e14de651234ecc08d9c03dc875a05f007b83eeb1193d38d2ce32d558a61f3f6377d65c2e342f87abc16f3897328cc54b2b61373e8258c18215cfe1766ab4610e0d2ec97a71fa1c62c9cb88f467a342832b6415dae8a7b3285fbf31b4e870b648d794bd0c6f70eb697f712b64ccfd2e103688a8f79d15eff71b7f57dece8f66e13be5ebbf1dc983b8183f3e1
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(55459);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/06/14");

  script_cve_id(
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0862",
    "CVE-2011-0863",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0867",
    "CVE-2011-0868",
    "CVE-2011-0869",
    "CVE-2011-0871",
    "CVE-2011-0873"
  );
  script_bugtraq_id(
    48137,
    48138,
    48140,
    48144,
    48145,
    48147,
    48148,
    48149
  );
  script_osvdb_id(
    73069,
    73070,
    73073,
    73074,
    73075,
    73076,
    73077,
    73081,
    73083,
    73084,
    73085,
    73176
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 5");
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
10.6 that is missing Update 5, which updates the Java version to
1.6.0_26.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 5, which includes version
13.5.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os)) 
  exit(0, "The host is running "+os+" and therefore is not affected.");

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

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.5.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 5)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 13.5.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since it is running Mac OS X 10.6 and has JavaVM Framework version "+version+".");
