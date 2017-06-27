#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15926);
 script_bugtraq_id(11757);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2013/09/06 15:56:05 $");

 script_cve_id("CVE-2006-4302");
 script_bugtraq_id(11757);
 script_osvdb_id(28109);

 script_name(english:"Sun Java Applet Invocation Version Specification");
 script_summary(english:"Checks for older versions of the Java SDK and JRE");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a runtime environment that is
affected by multiple vulnerabilities." );
 script_set_attribute(  attribute:"description",  value:
"The remote version of Windows contains a version of the Java JRE
that is older than 1.4.2_06 / 1.3.1_13.

Even if a newer version of this software is installed, a malicious
Java applet may invoke a particular version of the Java JRE to be
executed with. As a result, a rogue Java applet could exploit this 
vulnerability by requesting to be executed with an older, vulnerable 
version of the JRE." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securityfocus.com/archive/1/382281"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securityfocus.com/archive/1/382413"
 );
 # http://web.archive.org/web/20080605135514/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102557-1
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?0aabcce6"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Uninstall any outdated versions of the JRE."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/08/26");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

 script_dependencies("sun_java_jre_installed.nasl");
 script_require_keys("SMB/Java/JRE/Installed");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(0);

info = "";
vuln = 0;
foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver =~ "^(0\.|1\.[0-2]\.|1\.3\.0|1\.3\.1_([0-9]$|1[0-2]$)|1\.4\.([01]|2_0[0-5]))")
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver + '\n';
  }
}


# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity)
  {
    if (vuln > 1) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on the\n",
      "remote host :\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
