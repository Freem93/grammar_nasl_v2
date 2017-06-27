#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(92516);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2016-3458",
    "CVE-2016-3485",
    "CVE-2016-3498",
    "CVE-2016-3500",
    "CVE-2016-3503",
    "CVE-2016-3508",
    "CVE-2016-3511",
    "CVE-2016-3550",
    "CVE-2016-3552",
    "CVE-2016-3587",
    "CVE-2016-3598",
    "CVE-2016-3606",
    "CVE-2016-3610"
  );
  script_bugtraq_id(
    91904,
    91912,
    91918,
    91930,
    91945,
    91951,
    91956,
    91962,
    91972,
    91990,
    91996,
    92000,
    92006
  );
  script_osvdb_id(
    141824,
    141825,
    141826,
    141827,
    141828,
    141829,
    141830,
    141831,
    141832,
    141833,
    141834,
    141835,
    141836
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2016 CPU)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 101, 7 Update 111,
or 6 Update 121. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the CORBA subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-3458)

  - An unspecified flaw exists in the Networking
    subcomponent that allows a local attacker to impact
    integrity. (CVE-2016-3485)

  - An unspecified flaw exists in the JavaFX subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-3498)

  - An unspecified flaw exists in the JAXP subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3500)

  - An unspecified flaw exists in the Install subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3503)

  - An unspecified flaw exists in the JAXP subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3508)

  - An unspecified flaw exists in the Deployment
    subcomponent that allows a local attacker to gain
    elevated privileges. (CVE-2016-3511)

  - An unspecified flaw exists in the Hotspot subcomponent
    that allows an unauthenticated, remote attacker to
    disclose potentially sensitive information.
    (CVE-2016-3550)

  - An unspecified flaw exists in the Install subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3552)

  - A flaw exists in the Hotspot subcomponent due to
    improper access to the MethodHandle::invokeBasic()
    function. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-3587)

  - A flaw exists in the Libraries subcomponent within the
    MethodHandles::dropArguments() function that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-3598)

  - A flaw exists in the Hotspot subcomponent within the
    ClassVerifier::ends_in_athrow() function when handling
    bytecode verification. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2016-3606)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2016-3610)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?375663ac");
  # Java SE JDK and JRE 8 Update 101
  # http://www.oracle.com/technetwork/java/javase/8u101-relnotes-3021761.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92867054");
  # Java SE JDK and JRE 7 Update 111
  # http://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html#R170_111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77a46ced");
  # Java SE JDK and JRE 6 Update 121
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html#R160_121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a168366");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 101 / 7 Update 111 / 6 Update
121 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
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

  # Fixes : (JDK|JRE) 8 Update 101 / 7 Update 111 / 6 Update 121
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[01][0-9]|120)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|10[0-9]|110)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|100)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_121 / 1.7.0_111 / 1.8.0_101\n';
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
    exit(0, "The Java "+installed_versions+" installations on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
