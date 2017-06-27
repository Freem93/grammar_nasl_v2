#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64827);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");

  script_cve_id("CVE-2008-1193");
  script_bugtraq_id(28083, 28125);
  script_osvdb_id(42598);
  script_xref(name:"Secunia", value:"29239");

  script_name(english:"Sun Java JRE Multiple Vulnerabilities (233321-233327) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is affected by one or more security issues :

  - Two vulnerabilities in the JRE VM may independently allow
    an untrusted application or applet downloaded from a
    website to elevate its privileges (233321).

  - When processing XSLT transformations, an untrusted
    application or applet downloaded from a website may
    be able to elevate its privileges or cause the JRE to
    crash (233322).

  - Three buffer overflows exist in Java Web Start (233323).

  - A vulnerability in the Java Plug-in may allow an applet
    downloaded from a website to bypass the same origin
    policy and execute local applications (233324).

  - Multiple vulnerabilities in the JRE Image Processing
    library may allow an untrusted application or applet
    to elevate its privileges or cause the JRE to crash
    (233325).

  - A vulnerability in the JRE may allow untrusted
    JavaScript code to elevate its privileges through
    Java APIs (233326).

  - An as-yet unspecified buffer overflow exists in Java
    Web Start (233327).");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019016.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019017.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019018.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019018.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019020.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019021.1.html");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019021.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun JDK and JRE 6 Update 5 / JDK and JRE 5.0 Update 15 / SDK
and JRE 1.4.2_17 or later and remove, if necessary, any other affected
versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/04");

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
    ver =~ "^1\.6\.0_0[0-4][^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-4])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-6][^0-9]?))" ||
    ver =~ "^1\.3\."
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_05 / 1.5.0_15 / 1.4.2_17\n';
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
