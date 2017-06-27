#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96629);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/21 16:53:27 $");

  script_cve_id(
    "CVE-2016-2183",
    "CVE-2016-5546",
    "CVE-2016-5547",
    "CVE-2016-5548",
    "CVE-2016-5549",
    "CVE-2016-5552",
    "CVE-2016-8328",
    "CVE-2017-3231",
    "CVE-2017-3241",
    "CVE-2017-3252",
    "CVE-2017-3253",
    "CVE-2017-3259",
    "CVE-2017-3260",
    "CVE-2017-3261",
    "CVE-2017-3262",
    "CVE-2017-3272",
    "CVE-2017-3289"
  );
  script_bugtraq_id(
    92630,
    95488,
    95498,
    95506,
    95509,
    95512,
    95521,
    95525,
    95530,
    95533,
    95559,
    95563,
    95566,
    95570,
    95576,
    95578,
    95581
  );
  script_osvdb_id(
    143387,
    143388,
    150415,
    150416,
    150417,
    150418,
    150419,
    150420,
    150421,
    150422,
    150423,
    150424,
    150425,
    150426,
    150427,
    150428,
    150429,
    150430
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2017 CPU) (Unix) (SWEET32)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 121, 7 Update 131,
or 6 Update 141. It is, therefore, affected by multiple
vulnerabilities :

  - A vulnerability exists in the Libraries subcomponent,
    known as SWEET32, in the 3DES and Blowfish algorithms
    due to the use of weak 64-bit block ciphers by default.
    A man-in-the-middle attacker who has sufficient
    resources can exploit this vulnerability, via a
    'birthday' attack, to detect a collision that leaks the
    XOR between the fixed secret and a known plaintext,
    allowing the disclosure of the secret text, such as
    secure HTTPS cookies, and possibly resulting in the
    hijacking of an authenticated session. (CVE-2016-2183)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-5546)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-5547)

  - Multiple unspecified flaws exist in the Libraries
    subcomponent that allow an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5548, CVE-2016-5549)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-5552)

  - An unspecified flaw exists in the Mission Control
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-8328)

  - Multiple unspecified flaws exist in the Networking
    subcomponent that allow an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3231, CVE-2017-3261)

  - An unspecified flaw exists in the RMI subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3241)

  - An unspecified flaw exists in the JAAS subcomponent that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2017-3252)

  - An unspecified flaw exists in the 2D subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3253)

  - An unspecified flaw exists in the Deployment
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3259)

  - An unspecified flaw exists in the AWT subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3260)

  - An unspecified flaw exists in the Java Mission Control
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3262)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3272)

  - An unspecified flaw exists in the Hotspot subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3289)

Note that CVE-2017-3241 can only be exploited by supplying data to
APIs in the specified component without using untrusted Java Web Start
applications or untrusted Java applets, such as through a web service.
Note that CVE-2016-2183, CVE-2016-5546, CVE-2016-5547, CVE-2016-5552,
CVE-2017-3252, and CVE-2017-3253 can be exploited through sandboxed
Java Web Start applications and sandboxed Java applets. They can also
be exploited by supplying data to APIs in the specified component
without using sandboxed Java Web Start applications or sandboxed Java
applets, such as through a web service.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?951bfdb7");
  # http://www.oracle.com/technetwork/java/javase/8u121-relnotes-3315208.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3776cd3");
  # http://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f2226dc");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 121 / 7 Update 131 / 6 Update
141 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

  # Fixes : (JDK|JRE) 8 Update 121 / 7 Update 131 / 6 Update 141
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-3][0-9]|140)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-2][0-9]|130)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|1[0-1][0-9]|120)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_141 / 1.7.0_131 / 1.8.0_121\n';
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
