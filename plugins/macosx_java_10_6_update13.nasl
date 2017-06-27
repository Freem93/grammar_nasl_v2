#TRUSTED 1950b58cd635c33a91b289d9089309cc2761b6ce0717ee2497f13c56c6ecca5e3d514b6ca6be92ee1cddf3664ccb343cfd641648a0b9bfd7d4aff5081222acda3ef21bc7dc2c52720beace409d06688139c04ab645c95efb3c8001fdf518557e20ce1f2026a00068a61113035affc99e0dcef8c10ce54433627f1418f112c99da6cde672a8a7057973a3278f9f2e7e1bdaf24a76cd2bd7ea6ba2ffc5748159bb2dd309392ba67ae2f7b4963f690408b4fba69f8003737cba3959047ba9e4970b7a8313d5bbe7d0f2974d2777781fa6fdef59ebd3ebe4492ba6d8ed4cbc21faf9364f9b5226199d8537f2d87a3479795e1b916fb2eae69e5bd2103503162b226a1f79f81c015473cc423ab17d6da5613ef4263cd6ced2fe1e4e1d250eb7747d652696a503a9496f2433cb1c6c2da5a7f71def4faf9735b489ab2f32eb491f8de3e9f39fe3ae1aef63a101614fb595c86e371245177632f5493ea35219828ee0f2da042c5b1acff3e53c34dab570067038f1c9b91bed6728d7a31d160107638899b7f40e35eb8d7e9cb568ddec4c88cdc964353ca5e3e5ff3b51c4b267a01aea152212100bb0af4c4ce9f6c335182ee3260fe81b72744f00598185757947f97f600676dac2ad5e3c7858d751650a4d6fc6f46b0694b7b0c70c11a993f7ecdfb1252b26f03f941bac2f3749cf674b00adbf59f22f0eadfabe2308d3678c57512fde
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64699);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/11/14");

  script_cve_id("CVE-2013-1486", "CVE-2013-1487", "CVE-2013-1488");
  script_bugtraq_id(58029, 58031);
  script_osvdb_id(90352, 90353, 91472);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-19-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 13");
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
is missing Update 13, which updates the Java version to 1.6.0_41.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5666");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525745/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 13, which includes version
13.9.2 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

fixed_version = "13.9.2";
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
