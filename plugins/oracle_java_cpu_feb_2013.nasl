#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64454);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2012-1541",
    "CVE-2012-1543",
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2012-4301",
    "CVE-2012-4305",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0430",
    "CVE-2013-0431",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0436",
    "CVE-2013-0437",
    "CVE-2013-0438",
    "CVE-2013-0439",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0444",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0447",
    "CVE-2013-0448",
    "CVE-2013-0449",
    "CVE-2013-0450",
    "CVE-2013-1472",
    "CVE-2013-1473",
    "CVE-2013-1474",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1477",
    "CVE-2013-1478",
    "CVE-2013-1479",
    "CVE-2013-1480",
    "CVE-2013-1481",
    "CVE-2013-1482",
    "CVE-2013-1483",
    "CVE-2013-1489"
  );
  script_bugtraq_id(
    57681,
    57682,
    57683,
    57684,
    57685,
    57686,
    57687,
    57688,
    57689,
    57690,
    57691,
    57692,
    57693,
    57694,
    57695,
    57696,
    57697,
    57699,
    57700,
    57701,
    57702,
    57703,
    57704,
    57705,
    57706,
    57707,
    57708,
    57709,
    57710,
    57711,
    57712,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57719,
    57720,
    57721,
    57722,
    57723,
    57724,
    57725,
    57726,
    57727,
    57728,
    57729,
    57730,
    57731
  );
  script_osvdb_id(
    89613,
    89718,
    89758,
    89759,
    89760,
    89761,
    89762,
    89763,
    89764,
    89765,
    89766,
    89767,
    89768,
    89769,
    89771,
    89772,
    89773,
    89774,
    89775,
    89776,
    89777,
    89778,
    89779,
    89780,
    89781,
    89782,
    89783,
    89784,
    89785,
    89786,
    89787,
    89788,
    89789,
    89790,
    89791,
    89792,
    89793,
    89794,
    89795,
    89796,
    89797,
    89798,
    89799,
    89800,
    89801,
    89802,
    89803,
    89804,
    89805,
    89806
  );
  script_xref(name:"CERT", value:"858729");
  script_xref(name:"EDB-ID", value:"24539");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (February 2013 CPU)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 13 or 6 Update 39,
or is earlier than or equal to 5 Update 38 or 1.4.2 Update 40.  It is,
therefore, potentially affected by security issues in the following
components :

  - 2D
  - AWT
  - Beans
  - CORBA
  - Deployment
  - Install
  - JavaFX
  - JAXP
  - JAX-WS
  - JMX
  - JSSE
  - Libraries
  - Networking
  - RMI
  - Scripting
  - Sound");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Feb/12");
  script_set_attribute(attribute:"see_also", value:"http://www.security-explorations.com/en/SE-2012-01-details.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-010/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-011/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-012/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-013/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-022/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-023/");
  # http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a915dbbd");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 7 Update 13 or 6 Update 39 or later and, if
necessary, remove any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet JMX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");

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
    ver =~ '^1\\.4\\.2_([0-9]|[0-3][0-9]|40)([^0-9]|$)' ||
    ver =~ '^1\\.5\\.0_([0-9]|[0-2][0-9]|3[0-8])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-2][0-9]|3[0-8])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_(0[0-9]|1[0-2])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_39 / 1.7.0_13\n';
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
