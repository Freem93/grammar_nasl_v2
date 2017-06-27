#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64843);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-1321",
    "CVE-2010-3541",
    "CVE-2010-3548",
    "CVE-2010-3549",
    "CVE-2010-3550",
    "CVE-2010-3551",
    "CVE-2010-3552",
    "CVE-2010-3553",
    "CVE-2010-3554",
    "CVE-2010-3555",
    "CVE-2010-3556",
    "CVE-2010-3557",
    "CVE-2010-3558",
    "CVE-2010-3559",
    "CVE-2010-3560",
    "CVE-2010-3561",
    "CVE-2010-3562",
    "CVE-2010-3563",
    "CVE-2010-3565",
    "CVE-2010-3566",
    "CVE-2010-3567",
    "CVE-2010-3568",
    "CVE-2010-3569",
    "CVE-2010-3570",
    "CVE-2010-3571",
    "CVE-2010-3572",
    "CVE-2010-3573",
    "CVE-2010-3574"
  );
  script_bugtraq_id(
    43856,
    43965,
    43971,
    43979,
    43985,
    43988,
    43992,
    43994,
    43999,
    44009,
    44011,
    44012,
    44013,
    44014,
    44016,
    44017,
    44020,
    44021,
    44023,
    44024,
    44026,
    44027,
    44028,
    44030,
    44032,
    44035,
    44038,
    44040
  );
  script_osvdb_id(
    64744,
    68873,
    69033,
    69034,
    69035,
    69036,
    69037,
    69038,
    69039,
    69040,
    69041,
    69042,
    69043,
    69044,
    69045,
    69046,
    69047,
    69048,
    69049,
    69050,
    69051,
    69052,
    69053,
    69055,
    69056,
    69057,
    69058,
    69059,
    70083
  );
  script_xref(name:"Secunia", value:"41791");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2010 CPU) (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 6 Update 22 / 5.0 Update
26 / 1.4.2_28.  Such versions are potentially affected by security
issue in the following components :

  - CORBA
  - Deployment
  - Deployment Toolkit
  - Java 2D
  - Java Web Start
  - JNDI
  - JRE
  - JSSE
  - Kerberos
  - Networking
  - New Java Plug-in
  - Sound
  - Swing");
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2010-176258.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc96963b");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:"
Update to JDK / JRE 6 Update 22, JDK 5.0 Update 26, SDK 1.4.2_28 or
later and remove, if necessary, any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK 5.0 Update 26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start BasicServiceImpl Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
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
    ver =~ '^1\\.6\\.0_([0-9]|[01][0-9]|2[01])([^0-9]|$)' ||
    ver =~ '^1\\.5\\.0_([0-9]|[01][0-9]|2[0-5])([^0-9]|$)' ||
    ver =~ '^1\\.4\\.([01]_|2_([0-9]|[01][0-9]|2[0-7])([^0-9]|$))'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_22 / 1.5.0_26 / 1.4.2_28\n';
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
