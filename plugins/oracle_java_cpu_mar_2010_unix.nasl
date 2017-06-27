#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64842);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2009-3910",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0839",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0845",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0850"
  );
  script_bugtraq_id(
    36935,
    38973,
    39062,
    39065,
    39067,
    39068,
    39069,
    39070,
    39071,
    39072,
    39073,
    39075,
    39077,
    39078,
    39081,
    39082,
    39083,
    39084,
    39085,
    39086,
    39088,
    39089,
    39090,
    39091,
    39093,
    39094,
    39095,
    39096,
    39559
  );
  script_osvdb_id(
    63481,
    63482,
    63483,
    63484,
    63485,
    63486,
    63487,
    63488,
    63489,
    63490,
    63491,
    63492,
    63493,
    63494,
    63495,
    63496,
    63497,
    63498,
    63499,
    63500,
    63501,
    63502,
    63503,
    63504,
    63505,
    63506
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (March 2010 CPU) (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Unix host contains a runtime environment that is affected
by multiple vulnerabilities."
  );

  script_set_attribute(
    attribute:"description",
    value:
"The version of Oracle (formerly Sun) Java Runtime Environment (JRE)
installed on the remote host is earlier than 6 Update 19 / 5.0 Update
24 / 1.4.2_26.  Such versions are potentially affected by security
issues in the following components :

  - ImageIO
  - Java 2D
  - JRE
  - Java Web Start, Java Plug-in
  - Pack200
  - Sound
  - JSSE
  - HotSpot Server"
  );
  # http://www.oracle.com/technetwork/topics/security/whatsnew/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b93c78e2");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Update to JDK / JRE 6 Update 19, JDK 5.0 Update 24, SDK 1.4.2_26 or
later and remove, if necessary, any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK 5.0 Update 24 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
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
    ver =~ "^1\.6\.0_(0[0-9]|1[0-8])([^0-9]|$)" ||
    ver =~ "^1\.5\.0_([01][0-9]|2[0-3])([^0-9]|$)" ||
    ver =~ "^1\.4\.([01]_|2_([01][0-9]|2[0-5]([^0-9]|$)))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-7]([^0-9]|$)))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_19 / 1.5.0_24 / 1.4.2_26\n';
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
