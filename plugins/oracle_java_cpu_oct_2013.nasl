#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(70472);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id(
    "CVE-2013-3829",
    "CVE-2013-4002",
    "CVE-2013-5772",
    "CVE-2013-5774",
    "CVE-2013-5775",
    "CVE-2013-5776",
    "CVE-2013-5777",
    "CVE-2013-5778",
    "CVE-2013-5780",
    "CVE-2013-5782",
    "CVE-2013-5783",
    "CVE-2013-5784",
    "CVE-2013-5787",
    "CVE-2013-5788",
    "CVE-2013-5789",
    "CVE-2013-5790",
    "CVE-2013-5797",
    "CVE-2013-5800",
    "CVE-2013-5801",
    "CVE-2013-5802",
    "CVE-2013-5803",
    "CVE-2013-5804",
    "CVE-2013-5805",
    "CVE-2013-5806",
    "CVE-2013-5809",
    "CVE-2013-5810",
    "CVE-2013-5812",
    "CVE-2013-5814",
    "CVE-2013-5817",
    "CVE-2013-5818",
    "CVE-2013-5819",
    "CVE-2013-5820",
    "CVE-2013-5823",
    "CVE-2013-5824",
    "CVE-2013-5825",
    "CVE-2013-5829",
    "CVE-2013-5830",
    "CVE-2013-5831",
    "CVE-2013-5832",
    "CVE-2013-5838",
    "CVE-2013-5840",
    "CVE-2013-5842",
    "CVE-2013-5843",
    "CVE-2013-5844",
    "CVE-2013-5846",
    "CVE-2013-5848",
    "CVE-2013-5849",
    "CVE-2013-5850",
    "CVE-2013-5851",
    "CVE-2013-5852",
    "CVE-2013-5854"
  );
  script_bugtraq_id(
    58507,
    59141,
    59153,
    59165,
    59167,
    59170,
    59184,
    59187,
    59194,
    59206,
    59212,
    59213,
    59219,
    59228,
    59243,
    60617,
    60618,
    60619,
    60620,
    60621,
    60622,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60630,
    60631,
    60632,
    60633,
    60634,
    60635,
    60637,
    60638,
    60639,
    60640,
    60641,
    60643,
    60644,
    60645,
    60646,
    60647,
    60649,
    60650,
    60651,
    60652,
    60653,
    60654,
    60655,
    60656,
    60657,
    60658,
    60659,
    61310,
    63079,
    63082,
    63089,
    63095,
    63098,
    63101,
    63102,
    63103,
    63106,
    63110,
    63111,
    63112,
    63115,
    63118,
    63120,
    63121,
    63122,
    63124,
    63126,
    63127,
    63128,
    63129,
    63130,
    63131,
    63132,
    63133,
    63134,
    63135,
    63136,
    63137,
    63139,
    63140,
    63141,
    63142,
    63143,
    63144,
    63145,
    63146,
    63147,
    63148,
    63149,
    63150,
    63151,
    63152,
    63153,
    63154,
    63155,
    63156,
    63157,
    63158
  );
  script_osvdb_id(
    95418,
    98524,
    98525,
    98526,
    98527,
    98528,
    98529,
    98530,
    98531,
    98532,
    98533,
    98534,
    98535,
    98536,
    98537,
    98538,
    98539,
    98540,
    98541,
    98542,
    98543,
    98544,
    98545,
    98546,
    98547,
    98548,
    98549,
    98550,
    98551,
    98552,
    98553,
    98554,
    98555,
    98556,
    98557,
    98558,
    98559,
    98560,
    98561,
    98562,
    98563,
    98564,
    98565,
    98566,
    98567,
    98568,
    98569,
    98570,
    98571,
    98572,
    98573
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2013 CPU)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 45, 6 Update 65,
or 5 Update 55.  It is, therefore, potentially affected by security
issues in the following components :

  - 2D
  - AWT
  - BEANS
  - CORBA
  - Deployment
  - JAX-WS
  - JAXP
  - JGSS
  - jhat
  - JNDI
  - JavaFX
  - Javadoc
  - Libraries
  - SCRIPTING
  - Security
  - Swing");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-244/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-245/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-246/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-247/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-248/");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdc8b5c1");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 7 Update 45, 6 Update 65, or 5 Update 55 or later
and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 55 or later or 6 Update 65 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

  if (
    ver =~ '^1\\.5\\.0_([0-9]|[0-4][0-9]|5[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-5][0-9]|6[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-3][0-9]|4[0-4])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_55 / 1.6.0_65 / 1.7.0_45\n';
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
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
