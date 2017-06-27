#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64830);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");

  script_cve_id(
    "CVE-2009-0217",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2674",
    "CVE-2009-2675",
    "CVE-2009-2676"
  );
  script_bugtraq_id(
    35922,
    35939,
    35942,
    35943,
    35944,
    35945,
    35946,
    35958
  );
  script_osvdb_id(
    56243,
    56783,
    56784,
    56785,
    56786,
    56787,
    56788,
    56789,
    56984,
    57431
  );

  script_name(english:"Sun Java JRE Multiple Vulnerabilities (263408 / 263409 / 263428 ..) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a runtime environment that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is earlier than 6 Update 15 / 5.0 Update 20 / 1.4.2_22 /
1.3.1_26.  Such version are potentially affected by the following
security issues :

  - A vulnerability in the JRE audio system may allow system
    properties to be accessed. (263408)

  - A privilege escalation vulnerability may exist in the
    JRE SOCKS proxy implementation. (263409)

  - An integer overflow vulnerability when parsing JPEG
    images may allow an untrusted Java Web Start application
    to elevate privileges. (263428)

  - A vulnerability with verifying HMAC-based XML digital
    signatures in the XML Digital Signature implementation
    may allow authentication to be bypassed. (263429)

  - An integer overflow vulnerability with unpacking applets
    and Java Web start applications using the 'unpack200' JAR
    unpacking utility may allow an untrusted applet to
    elevate privileges. (263488)

  - An issue with parsing XML data may allow a remote client
    to create a denial of service condition. (263489)

  - Non-current versions of the 'JNLPAppletLauncher' may be
    re-purposed with an untrusted Java applet to write
    arbitrary files. (263490)");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020707.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020708.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020709.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020710.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020712.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020713.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020714.1.html");
  script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK / JRE 6 Update 15, JDK / JRE 5.0 Update 20, SDK
/ JRE 1.4.2_22, or SDK / JRE 1.3.1_26 or later and remove, if necessary,
any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("Host/Java/JRE/Unmanaged/*");

info = "";
vuln = 0;
vuln2 = 0;
installed_versions = "";
granular = "";
foreach install (list_uniq(keys(installs)))
{
  ver = install - "Host/Java/JRE/Unmanaged/";
  if (ver !~ "^[0-9.]+") continue;
  installed_versions = installed_versions + " & " + ver;
  if (
    ver =~ "^1\.6\.0_(0[0-9]|1[0-4])([^0-9]|$)" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-9])([^0-9]|$)" ||
    ver =~ "^1\.4\.([01]_|2_([01][0-9]|2[01]([^0-9]|$)))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-5]([^0-9]|$)))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_15 / 1.5.0_20 / 1.4.2_22 / 1.3.1_26\n';
  }
  else if (ver =~ "^[\d\.]+$")
  {
    dirs = make_list(get_kb_list(install));
    foreach dir (dirs)
      granular += "The Oracle Java version "+ver+" at "+dir+" is not granular enough to make a determination."+'\n';
  }
  else
  {
    dirs = make_list(get_kb_list(install));
    vuln2 += max_index(dirs);
  }

}

# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Java are";
    else s = " of Java is";

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      info;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  if (granular) exit(0, granular);
}
else
{
  if (granular) exit(0, granular);

  installed_versions = substr(installed_versions, 3);
  if (vuln2 > 1)
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    exit(0, "The Java "+installed_versions+" install on the remote host is not affected.");
}
