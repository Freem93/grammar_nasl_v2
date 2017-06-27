#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(71966);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2013-5870",
    "CVE-2013-5878",
    "CVE-2013-5884",
    "CVE-2013-5887",
#   "CVE-2013-5888", << GNOME on *nix only
    "CVE-2013-5889",
    "CVE-2013-5893",
    "CVE-2013-5895",
    "CVE-2013-5896",
    "CVE-2013-5898",
    "CVE-2013-5899",
    "CVE-2013-5902",
    "CVE-2013-5904",
    "CVE-2013-5905",
    "CVE-2013-5906",
    "CVE-2013-5907",
    "CVE-2013-5910",
    "CVE-2014-0368",
    "CVE-2014-0373",
    "CVE-2014-0375",
    "CVE-2014-0376",
    "CVE-2014-0382",
    "CVE-2014-0385",
    "CVE-2014-0387",
    "CVE-2014-0403",
    "CVE-2014-0408",
    "CVE-2014-0410",
    "CVE-2014-0411",
    "CVE-2014-0415",
    "CVE-2014-0416",
    "CVE-2014-0417",
    "CVE-2014-0418",
    "CVE-2014-0422",
    "CVE-2014-0423",
    "CVE-2014-0424",
    "CVE-2014-0428"
  );
  script_bugtraq_id(
    64863,
    64875,
    64882,
    64890,
    64894,
    64899,
    64901,
    64903,
    64906,
    64907,
    64910,
    64912,
    64914,
    64915,
    64916,
    64917,
    64918,
    64919,
    64920,
    64921,
    64922,
    64923,
    64924,
    64926,
    64927,
    64928,
    64929,
    64930,
    64931,
    64932,
    64933,
    64934,
    64935,
    64936,
    64937
  );
  script_osvdb_id(
    101993,
    101994,
    101995,
    101996,
    101997,
    101998,
    101999,
    102000,
    102001,
    102002,
    102003,
    102004,
    102005,
    102006,
    102007,
    102008,
    102009,
    102010,
    102011,
    102012,
    102013,
    102014,
    102015,
    102016,
    102017,
    102018,
    102019,
    102020,
    102021,
    102022,
    102024,
    102025,
    102026,
    102027,
    102028
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2014 CPU)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 51, 6 Update 71,
or 5 Update 61.  It is, therefore, potentially affected by security
issues in the following components :

  - 2D
  - Beans
  - CORBA
  - Deployment
  - Hotspot
  - Install
  - JAAS
  - JavaFX
  - JAXP
  - JNDI
  - JSSE
  - Libraries
  - Networking
  - Security
  - Serviceability");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-013/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-038/");
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15ecb462");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 7 Update 51, 6 Update 71 or 5 Update 61 or later
and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 61 or later or 6 Update 71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
    ver =~ '^1\\.5\\.0_([0-9]|[0-5][0-9]|60)([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-6][0-9]|70)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-4][0-9]|50)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_61 / 1.6.0_71 / 1.7.0_51\n';
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
