#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64836);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/08/19 21:24:45 $");

  script_cve_id("CVE-2005-1973", "CVE-2005-1974");
  script_bugtraq_id(13958, 13945);
  script_osvdb_id(17299, 17340);
  script_xref(name:"Secunia", value:"15671");

  script_name(english:"Sun Java JRE / Web Start Java Plug-in Untrusted Applet Privilege Escalation (Unix)");
  script_summary(english:"Determines the version of Java JRE plugin");

  script_set_attribute( attribute:"synopsis", value:
"The remote Unix host contains a runtime environment that is affected by
multiple vulnerabilities.");
  script_set_attribute( attribute:"description",  value:

"The remote host is using an unmanaged version of Sun Java Runtime
Environment that has vulnerabilities in its Java Runtime Plug-in, a web
browser add-on used to display Java applets.

The JRE Plug-in security can be bypassed by tricking a user into viewing
a maliciously crafted web page.

Additionally, a denial of service vulnerability is present in this
version of the JVM.  This issue is triggered by viewing an applet that
misuses the serialization API.");
  # http://web.archive.org/web/20080509045533/http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0103e844");
  script_set_attribute(attribute:"solution", value:"Upgrade to JRE 1.4.2_08 / 1.5.0 update 2 or later.");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/13");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
    ver =~ "^1\.4\.([01]_|2_0*[0-7][^0-9])" ||
    ver =~ "^1\.5\.0_0*[01][^0-9]"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.4.2_08 / 1.5.0_02\n';
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
