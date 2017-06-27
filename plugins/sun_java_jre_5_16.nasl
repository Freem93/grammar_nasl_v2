#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33487);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3106", "CVE-2008-3107",
                "CVE-2008-3108", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113",
                "CVE-2008-3114", "CVE-2008-3115");
  script_bugtraq_id(30140, 30141, 30142, 30143, 30146, 30147, 30148);
  script_xref(name:"OSVDB", value:"46955");
  script_xref(name:"OSVDB", value:"46956");
  script_xref(name:"OSVDB", value:"46957");
  script_xref(name:"OSVDB", value:"46958");
  script_xref(name:"OSVDB", value:"46959");
  script_xref(name:"OSVDB", value:"46962");
  script_xref(name:"OSVDB", value:"46963");
  script_xref(name:"OSVDB", value:"46965");
  script_xref(name:"OSVDB", value:"46966");
  script_xref(name:"OSVDB", value:"46967");

  script_name(english:"Sun Java JDK/JRE 5 < Update 16 Multiple Vulnerabilities" );
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) 5.0 installed on the
remote host is affected by multiple security issues :

- A vulnerability in the XML processing module of the JRE could allow 
  an untrusted applet/application unauthorized access to certain URL 
  resources (238628).

- A buffer overflow vulnerability in font processing module of the JRE,
  could allow an untrusted applet/application to elevate its privileges
  to read, write and execute local applications with privileges of the
  user running an untrusted applet (238666). Note this issue only affects 
  Sun Java JDK/JRE 5 Update 9 and earlier.

- A buffer overflow vulnerability in Java Web Start, could allow an
  untrusted applet to elevate its privileges to read, write and
  execute local applications available to user running an untrusted
  application (238905).

- A vulnerability in Java Web Start, could allow an untrusted
  application to create or delete arbitrary files subject to
  the privileges of the user running the application (238905).

- A vulnerability in Java Web Start, may disclose the location of
  Java Web Start cache (238905).

- Vulnerability in Sun Java Management Extensions (JMX) could allow a
  JMX client running on a remote host to perform unauthorized actions
  on a host running JMX with local monitoring enabled (238965).

- An implementation defect in the JRE, may allow an applet designed to run
  'only' on JRE 5.0 Update 6 or later may run on older releases of the JRE.
  Note this only affects Windows Vista releases of the JRE (238966).

- A vulnerability in the JRE could allow an untrusted applet/application
  to elevate its privileges to read, write and execute local applications
  with privileges of the user running an untrusted applet (238967).

- A vulnerability in the JRE may allow an untrusted applet to establish
  connections to services running on the localhost and potentially
  exploit vulnerabilities existing in the underlying JRE (238968)." );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019338.1.html" );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019342.1.html" );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019367.1.html" );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019373.1.html" );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019375.1.html" );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019376.1.html" );
 script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK and JRE 5 Update 16 or later and remove if
necessary any affected versions." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(16, 20, 119, 200, 264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/15");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/07/08");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(1, "The 'SMB/Java/JRE/' KB item is missing.");

info = "";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver =~ "^[0-9.]+")
    installed_versions = installed_versions + " & " + ver;
  if (ver =~ "^1\.5\.0_(0[0-9]|1[0-5])[^0-9]?")
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_16\n';
  }
}


# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Java are";
    else s = " of Java is";

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (" & " >< installed_versions)
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    exit(0, "The Java "+installed_versions+" install on the remote host is not affected.");
}
