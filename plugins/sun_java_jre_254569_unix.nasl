#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64829);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id(
    "CVE-2006-2426",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1102",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1105",
    "CVE-2009-1106",
    "CVE-2009-1107"
  );
  script_bugtraq_id(34240);
  script_osvdb_id(
    25561,
    53164,
    53165,
    53166,
    53167,
    53168,
    53169,
    53170,
    53171,
    53172,
    53173,
    53174,
    53175,
    53176,
    53177,
    53178
  );

  script_name(english:"Sun Java JRE Multiple Vulnerabilities (254569 / 254611 / 254608 ..) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a runtime environment that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is earlier than 6 Update 13 / 5.0 Update 18 / 1.4.2_20 /
1.3.1_25.  Such versions are potentially affected by the following
security issues :

  - A denial of service vulnerability affects the JRE LDAP
    implementation. (254569).

  - A remote code execution vulnerability in the JRE LDAP
    implementation may allow for arbitrary code to be run in
    the context of the affected LDAP client. (254569)

  - There are multiple integer and buffer overflow
    vulnerabilities when unpacking applets and Java Web
    Start applications using the 'unpack2000' utility.
    (254570)

  - There are multiple denial of service vulnerabilities
    related to the storing and processing of temporary font
    files. (254608)

  - A privilege escalation vulnerability affects the Java
    Plug-in when deserializing applets. (254611)

  - A weakness in the Java Plug-in allows JavaScript loaded
    from the localhost to connect to arbitrary ports on the
    local system. (254611)

  - A vulnerability in the Java Plug-in allows malicious
    JavaScript code to exploit vulnerabilities in earlier
    versions of the JRE that have been loaded by an applet
    located on the same web page. (254611)

  - An issue exists in the Java Plug-in when parsing
    'crossdomain.xml' allows an untrusted applet to connect
    to an arbitrary site hosting a 'crossdomain.xml' file.
    (254611)

  - The Java Plug-in allows a malicious signed applet to
    obscure the contents of a security dialog. (254611)

  - The JRE Virtual Machine is affected by a
    privilege escalation vulnerability. (254610)

  - There are multiple buffer overflow vulnerabilities
    involving the JRE's processing of PNG and GIF images.
    (254571)

  - There are multiple buffer overflow vulnerabilities
    involving the JRE's processing of fonts. (254571)

  - A denial of service vulnerability affected the JRE HTTP
    server implementation, which could be used to cause a
    denial of service on a JAX-WS service endpoint. (254609)");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020224.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020225.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020226.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020228.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020229.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020230.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020231.1.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u13-142696.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/index.html");
  script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK / JRE 6 Update 13, JDK / JRE 5.0 Update 18, SDK
/ JRE 1.4.2_20, or SDK / JRE 1.3.1_25 or later and remove, if necessary,
any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 94, 119, 189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/24");

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
    ver =~ "^1\.6\.0_(0[0-9]|1[0-2])([^0-9]|$)" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-7])([^0-9]|$)" ||
    ver =~ "^1\.4\.([01]_|2_([01][0-9]([^0-9]|$)))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-4]([^0-9]|$)))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_13 / 1.5.0_18 / 1.4.2_20 / 1.3.1_25\n';
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
