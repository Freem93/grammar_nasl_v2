#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64824);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");

  script_cve_id(
    "CVE-2007-5232",
    "CVE-2007-5236",
    "CVE-2007-5237",
    "CVE-2007-5238",
    "CVE-2007-5239",
    "CVE-2007-5240",
    "CVE-2007-5273",
    "CVE-2007-5274",
    "CVE-2007-5689"
  );
  script_bugtraq_id(25918, 25920, 26185);
  script_osvdb_id(
    37759,
    37760,
    37761,
    37762,
    37763,
    37764,
    37765,
    40834,
    45527
  );

  script_name(english:"Sun Java JRE / Web Start Multiple Vulnerabilities (103072, 103073, 103078, 103079, 103112) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Sun Java Runtime Environment (JRE)
and/or Web Start installed on the remote host is reportedly affected by
several issues that could be abused to move / copy local files, read or
write local files, circumvent network access restrictions, or elevate
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://conference.hitb.org/hitbsecconf2007kl/?page_id=148");
  # http://web.archive.org/web/20080129213300/http://sunsolve.sun.com/search/document.do?assetkey=1-26-103072-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d88f8c90");
  # http://web.archive.org/web/20080129213305/http://sunsolve.sun.com/search/document.do?assetkey=1-26-103073-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3744db68");
  # http://web.archive.org/web/20080622195736/http://sunsolve.sun.com/search/document.do?assetkey=1-26-103078-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dd067e0");
  # http://web.archive.org/web/20080609024942/http://sunsolve.sun.com/search/document.do?assetkey=1-26-103079-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cbab94e");
  # http://web.archive.org/web/20071027024719/http://sunsolve.sun.com/search/document.do?assetkey=1-26-103112-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?811a9446");
  script_set_attribute(attribute:"solution", value:
"Update to Sun JDK and JRE 6 Update 3 / JDK and JRE 5.0 Update 13 / SDK
and JRE 1.4.2_16 / SDK and JRE 1.3.1_21 or later and remove, if
necessary, any other affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
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
    ver =~ "^1\.6\.0_0[0-2][^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-2])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-5][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|20[^0-9]?))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_03 / 1.5.0_13 / 1.4.2_16 / 1.3.1_21\n';
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
