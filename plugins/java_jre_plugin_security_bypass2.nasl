#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(18480);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2013/08/19 21:24:45 $");

 script_cve_id("CVE-2005-1973", "CVE-2005-1974");
 script_bugtraq_id(13958, 13945);
 script_xref(name:"OSVDB", value:"17299");
 script_xref(name:"OSVDB", value:"17340");
 script_xref(name:"Secunia", value:"15671");

 script_name(english:"Sun Java JRE / Web Start Java Plug-in Untrusted Applet Privilege Escalation");
 script_summary(english:"Determines the version of Java JRE plugin");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a runtime environment that is
affected by multiple vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The remote host is using a vulnerable version of Sun Java Runtime
Plug-in, an web browser addon used to display Java applets.

It has been reported that the JRE Plug-in Security can be bypassed.
A remote attacker could exploit this by tricking a user into viewing
a maliciously crafted web page.

Additionally, a denial of service vulnerability is present in this
version of the JVM.  This issue is triggered by viewing an applet
that misuses the serialization API." );
 # http://web.archive.org/web/20080509045533/http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?0103e844"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to JRE 1.4.2_08 / 1.5.0 update 2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/13");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/06/13");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 
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
