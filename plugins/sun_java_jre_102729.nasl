#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23931);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745");
  script_bugtraq_id(21673, 21674, 21675);
  script_xref(name:"OSVDB", value:"32357");
  script_xref(name:"OSVDB", value:"32358");
  script_xref(name:"OSVDB", value:"32393");
  script_xref(name:"OSVDB", value:"32394");
  script_xref(name:"OSVDB", value:"32931");
  script_xref(name:"OSVDB", value:"32932");
  script_xref(name:"OSVDB", value:"32933");
  script_xref(name:"OSVDB", value:"32934");

  script_name(english:"Sun Java JRE Multiple Vulnerabilities (102729 / 102732)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a version of Sun's Java Runtime
Environment that is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sun JRE installed on the remote
host has two buffer overflow issues that may allow an untrusted applet
to elevate its privileges to, for example, read or write local files
or to execute local applications subject to the privileges of the user
running the applet. 

In addition, another set of vulnerabilities may allow an untrusted
applet to access data in other applets." );
 script_set_attribute(attribute:"see_also", value:"http://scary.beasts.org/security/CESA-2005-008.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58f88e57");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6507bb6f");
 script_set_attribute(attribute:"solution", value:
"Update to Sun Java 2 JDK and JRE 5.0 Update 8 / SDK and JRE 1.4.2_13 /
SDK and JRE 1.3.1_19 or later and remove if necessary any affected
versions." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/12/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/19");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

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
    ver =~ "^1\.5\.0_0[0-7][^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-2][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_(0[0-9]|1[0-8][^0-9]?))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_08 / 1.4.2_13 / 1.3.1_19\n';
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
