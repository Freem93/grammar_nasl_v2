#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(61681);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2012-0547",
    "CVE-2012-1682",
    "CVE-2012-3136",
    "CVE-2012-4681"
  );
  script_bugtraq_id(55213, 55336, 55337, 55339);
  script_osvdb_id(84867, 84980, 84981, 84982);
  script_xref(name:"CERT", value:"636312");
  script_xref(name:"EDB-ID", value:"20865");

  script_name(english:"Oracle Java SE 7 < Update 7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 7 and is,
therefore, potentially affected the following vulnerabilities :

  - The 'getField' method in the 'sun.awt.SunToolkit class'
    provided by the bundled SunToolkit can be used to
    obtain any field of a class - even private fields.
    This error can allow privilege escalation.
    (CVE-2012-0547)

  - Two unspecified remote code execution vulnerabilities
    exist related to the
    'com.sun.beans.finder.ConstructorFinder' and
    'com.sun.beans.finder.FieldFinder' methods. No further
    details have been provided. (CVE-2012-1682,
    CVE-2012-3136)

  - The 'setField' method provided by the bundled SunToolkit
    can be used to execute a privileged operation and calls
    'setAccessible(true)' on the returned field reference,
    allowing an attacker to disable any 'final' or 'private'
    directives and gain full control to run code in the Java
    virtual machine. (CVE-2012-4681)

Note that at least one of these vulnerabilities is currently being
exploited in the wild.");

  # http://blog.fireeye.com/research/2012/08/zero-day-season-is-not-over-yet.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26d19d73");
  # http://www.deependresearch.org/2012/08/java-7-0-day-vulnerability-information.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?563cdce7");
  # http://thexploit.com/sec/java-facepalm-suntoolkit-getfield-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83fce915");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/7u7-relnotes-1835816.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JDK / JRE 7 Update 7 or later, and remove, if necessary, 
any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java 7 Applet Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("SMB/Java/JRE/*");

info = "";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  if (ver =~ '^1\\.7\\.0_0[0-6]([^0-9]|$)')
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_07\n';
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
