#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64828);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

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
    "CVE-2008-5355",
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5358",
    "CVE-2008-5359",
    "CVE-2008-5360"
  );
  script_bugtraq_id(30633, 32608, 32620, 32892);
  script_osvdb_id(
    50495,
    50496,
    50497,
    50498,
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
    50515,
    50516,
    50517
  );

  script_name(english:"Sun Java JRE Multiple Vulnerabilities (244986 et al) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a runtime environment that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is earlier than 6 Update 11 / 5.0 Update 17 / 1.4.2_19 /
1.3.1_24.  Such versions are potentially affected by the following
security issues :

  - The JRE creates temporary files with insufficiently
    random names. (244986)

  - There are multiple buffer overflow vulnerabilities
    involving the JRE's image processing code, its
    handling of GIF images, and its font processing.
    (244987)

  - It may be possible for an attacker to bypass security
    checks due to the manner in which it handles the
    'non-shortest form' of UTF-8 byte sequences.

  - There are multiple security vulnerabilities in Java
    Web Start and Java Plug-in that may allow for privilege
    escalation. (244988)

  - The JRE Java Update mechanism does not check the digital
    signature of the JRE that it downloads. (244989)

  - A buffer overflow may allow an untrusted Java
    application that is launched through the command line to
    elevate its privileges. (244990)

  - A vulnerability related to deserializing calendar
    objects may allow an untrusted applet or application to
    elevate its privileges. (244991)

  - A buffer overflow affects the 'unpack200' JAR unpacking
    utility and may allow an untrusted applet or application
    to elevate its privileges with unpacking applets and
    Java Web Start applications. (244992)

  - The UTF-8 decoder accepts encodings longer than the
    'shortest' form. Although not a vulnerability per se,
    it may be leveraged to exploit software that relies on
    the JRE UTF-8 decoder to reject the 'non-shortest form'
    sequence. (245246)

  - An untrusted applet or application may be able to list
    the contents of the home directory of the user running
    the applet or application. (246266)

  - A denial of service vulnerability may be triggered when
    the JRE handles certain RSA public keys. (246286)

  - A vulnerability may be triggered while authenticating
    users through Kerberos and lead to a system-wide denial
    of service due to excessive consumption of operating
    system resources. (246346)

  - Security vulnerabilities in the JAX-WS and JAXB packages
    where internal classes can be accessed may allow an
    untrusted applet or application to elevate privileges.
    (246366)

  - An untrusted applet or application when parsing zip
    files may be able to read arbitrary memory locations in
    the process that the applet or application is running.
    (246386)

  - The JRE allows code loaded from the local filesystem to
    access localhost. (246387)");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019736.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019737.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019738.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019739.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019740.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019741.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019742.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019759.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019793.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019794.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019797.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019798.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019799.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019800.1.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u11-139394.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/index.html");
  script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK / JRE 6 Update 11, JDK / JRE 5.0 Update 17, SDK
/ JRE 1.4.2_19, or SDK / JRE 1.3.1_24 or later and remove, if necessary,
any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189, 200, 264, 287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/03");
 
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
    ver =~ "^1\.6\.0_(0[0-9]|10)([^0-9]|$)" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-6])([^0-9]|$)" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-8]([^0-9]|$)))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-3]([^0-9]|$)))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_11 / 1.5.0_17 / 1.4.2_19 / 1.3.1_24\n';
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
