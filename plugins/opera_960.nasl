#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34368);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-4694", "CVE-2008-4695");
  script_bugtraq_id(31631, 31643);
  script_osvdb_id(49093, 49094);
  script_xref(name:"Secunia", value:"32177");
  
  script_name(english:"Opera < 9.60 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 9.60
and thus reportedly affected by several issues :

  - Specially crafted URLs can cause Opera to crash or allow
    arbitrary code execution.

  - Once a Java applet has been cached, a page that can
    predict the cache path for that applet can load it from
    cache thereby causing it to run in the security context
    of the local machine, allowing for reading of other
    files from the cache." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/901/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/902/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/960/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 9.60 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(59, 200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/08");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 || 
  (
    ver[0] == 9 && 
    (
      ver[1] < 60 ||
      (ver[1] == 60 && ver[2] < 10447)
    )
  )
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
