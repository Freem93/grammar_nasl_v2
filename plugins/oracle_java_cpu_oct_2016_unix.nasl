#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(94139);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/08 21:08:21 $");

  script_cve_id(
    "CVE-2016-5542",
    "CVE-2016-5554",
    "CVE-2016-5556",
    "CVE-2016-5568",
    "CVE-2016-5573",
    "CVE-2016-5582",
    "CVE-2016-5597"
  );
  script_bugtraq_id(
    93618,
    93621,
    93623,
    93628,
    93636,
    93637,
    93643
  );
  script_osvdb_id(
    145944,
    145945,
    145946,
    145947,
    145948,
    145949,
    145950
  );
  script_xref(name:"EDB-ID", value:"118073");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2016 CPU) (Unix)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 111, 7 Update 121,
or 6 Update 131. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the Libraries
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-5542)

  - An unspecified flaw exists in the JMX subcomponent that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2016-5554)

  - An unspecified flaw exists in the 2D subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-5556)

  - An unspecified flaw exists in the AWT subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-5568)

  - Multiple unspecified flaws exist in the Hotspot
    subcomponent that allow an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-5573,
    CVE-2016-5582)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5597)");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  # Java SE JDK and JRE 8 Update 111
  # http://www.oracle.com/technetwork/java/javase/8u111-relnotes-3124969.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2118655a");
  # Java SE JDK and JRE 7 Update 121
  # http://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f2226dc");
  # Java SE JDK and JRE 6 Update 131
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 111 / 7 Update 121 / 6 Update
131 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

  # Fixes : (JDK|JRE) 8 Update 111 / 7 Update 121 / 6 Update 131
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-2][0-9]|130)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-1][0-9]|120)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|10[0-9]|110)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_131 / 1.7.0_121 / 1.8.0_111\n';
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
    exit(0, "The Java "+installed_versions+" installations on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
