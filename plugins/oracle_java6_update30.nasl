#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57290);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");
  script_osvdb_id(78666,78667,78668,78669,78670,78671);

  script_name(english:"Oracle Java JDK / JRE 6 < Update 30 Multiple Vulnerabilities");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a runtime environment that is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value: 
"The version of Oracle (formerly Sun) Java Runtime Environment (JRE)
6.x installed on the remote host is earlier than Update 30 and is
potentially affected by the following vulnerabilities:

  - A stack overflow error exists related to proxy
    tunnels. (Bug #6670868)

  - An error exists related to foreach loops containing
    generics that could lead to javac crashses. 
    (Bug #6682380)
    
  - An error exists related to security exceptions in
    'AnnotationInvocationHandler.getMemberMethods'. 
   (Bug #6761678)

  - An error in 'URI.equals' could allow a return value of 
    'true' when handling escaped octets. (Bug #7041800)

  - An error related to 'liveconnect' could cause secure
    cookies not to be transfered. (Bug #7102914)

  - SSL connectivity is broken when using the cipher suite
    TLS_DH_anon_WITH_AES_128_CBC_SHA. (Bug #7103725)");

  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u30-relnotes-1394870.html");
  # http://www.oracle.com/technetwork/java/javase/2col/6u30bugfixes-1394936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b71ebd2");
  # http://krebsonsecurity.com/wp-content/uploads/2011/12/java6update30notes.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84047d12");
  # http://krebsonsecurity.com/2011/12/security-updates-for-microsoft-windows-java/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8ddaa5f");
  script_set_attribute(attribute:"see_also", value:"http://mail.openjdk.java.net/pipermail/jdk6-dev/2008-October/000232.html");
  script_set_attribute(attribute:"see_also", value:"http://blogs.oracle.com/javase/entry/java_7_update_2_and");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 6 Update 30 or later and remove, if necessary, 
any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("SMB/Java/JRE/*");

info="";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  if (ver =~ '^1\\.6\\.0_([0-9]|[0-2][0-9])([^0-9]|$)')
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_30\n';
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
