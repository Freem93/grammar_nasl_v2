#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64831);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id(
    "CVE-2009-3728",
    "CVE-2009-3729",
    "CVE-2009-3864",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3876",
    "CVE-2009-3877",
    "CVE-2009-3879",
    "CVE-2009-3880",
    "CVE-2009-3881",
    "CVE-2009-3884",
    "CVE-2009-3885",
    "CVE-2009-3886"
  );
  script_bugtraq_id(36881);
  script_osvdb_id(
    59705,
    59706,
    59707,
    59708,
    59709,
    59710,
    59711,
    59712,
    59713,
    59714,
    59715,
    59716,
    59717,
    59718,
    59917,
    59918,
    59919,
    59920,
    59921,
    59922,
    59923,
    59924
  );

  script_name(english:"Sun Java JRE Multiple Vulnerabilities (269868 / 269869 / 270476 ...) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Unix host contains a runtime environment that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is earlier than 6 Update 17 / 5.0 Update 22 / 1.4.2_24 /
1.3.1_27.  Such versions are potentially affected by the following
security issues :

  - The Java update mechanism on non-English versions does
    not update the JRE when a new version is available.
    (269868)

  - A command execution vulnerability exists in the Java
    runtime environment deployment toolkit. (269869)

  - An issue in the Java web start installer may be
    leveraged to allow an untrusted Java web start
    application to run as a trusted application. (269870)

  - Multiple buffer and integer overflow vulnerabilities
    exist. (270474)

  - A security vulnerability in the JRE with verifying HMAC
    digests may allow authentication to be bypassed.
    (270475)

  - Two vulnerabilities in the JRE with decoding DER encoded
    data and parsing HTTP headers may separately allow a
    remote client to cause the JRE on the server to run out
    of memory, resulting in a denial of service. (270476)

  - A directory traversal vulnerability in the
    ICC_Profile.getInstance method allows a remote attacker
    to determine the existence of local International Color
    Consortium (ICC) profile files. (Bug #6631533)

  - A denial of service attack is possible via a BMP file
    containing a link to a UNC share pathname for an
    International Color Consortium (ICC) profile file.
    (Bug #6632445)

  - Resurrected classloaders can still have children,
    which could allow a remote attacker to gain
    privileges via unspecified vectors (Bug #6636650)

  - The Abstract Window Toolkit (AWT) does not properly
    restrict the objects that may be sent to loggers, which
    allows attackers to obtain sensitive information via
    vectors related to the implementation of Component,
    KeyboardFocusManager, and DefaultKeyboardFocusManager.
    (Bug #6664512)

  - An unspecified vulnerability in TrueType font parsing
    functionality may lead to a denial of service. (Bug
    #6815780)

  - The failure to clone arrays returned by the
    getConfigurations function could lead to multiple,
    unspecified vulnerabilities in the X11 and
    Win32GraphicsDevice subsystems. (Bug #6822057)

  - The TimeZone.getTimeZone method can be used by a remote
    attacker to determine the existence of local files via
    its handling of zoneinfo (aka tz) files. (Bug #6824265)

  - Java Web Start does not properly handle the interaction
    between a signed JAR file and a JNLP application or
    applet. (Bug #6870531)"
  );
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1021046.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1021046.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1021048.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1021048.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1021083.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1021084.1.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Update to Sun Java JDK / JRE 6 Update 17, JDK / JRE 5.0 Update 22, SDK
/ JRE 1.4.2_24, or SDK / JRE 1.3.1_27 or later and remove, if necessary,
any affected versions."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 94, 119, 189, 200, 264, 310, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/03");
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
    ver =~ "^1\.6\.0_(0[0-9]|1[0-6])([^0-9]|$)" ||
    ver =~ "^1\.5\.0_([01][0-9]|2[01])([^0-9]|$)" ||
    ver =~ "^1\.4\.([01]_|2_([01][0-9]|2[0-3]([^0-9]|$)))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-6]([^0-9]|$)))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_17 / 1.5.0_22 / 1.4.2_24 / 1.3.1_27\n';
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
