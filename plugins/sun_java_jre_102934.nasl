#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25370);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2007-2788", "CVE-2007-2789");
  script_bugtraq_id(24004);
  script_osvdb_id(36199, 36200);

  script_name(english:"Sun Java JRE Image Parsing Vulnerabilities (102934)");
  script_summary(english:"Checks version of Sun JRE"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by several
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its version number, the Sun Java Runtime Environment
(JRE) installed on the remote host reportedly is affected by a buffer
overflow in its image processing code as well as another issue that
may cause the Java Virtual Machine to hang." );
  # http://web.archive.org/web/20080503165106/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102934-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?328117fc");
  script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK and JRE 6 Update 1 / JDK and JRE 5.0 Update 11
/ SDK and JRE 1.3.1_20 or later and remove if necessary any affected
versions." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/02");
  script_set_attribute(attribute:"patch_publication_date", value: "2007/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/16");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

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
  if (
    ver =~ "^1\.6\.0_00" ||
    ver =~ "^1\.5\.0_(0[0-9]|10)[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-4][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_[01][0-9])"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_01 / 1.5.0_11 / 1.3.1_20\n';
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
