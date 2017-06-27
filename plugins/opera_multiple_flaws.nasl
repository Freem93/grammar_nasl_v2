#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11404);
 script_version("$Revision: 1.23 $");
 script_cve_id("CVE-2002-2414", "CVE-2003-1387", "CVE-2003-1397", "CVE-2003-1420");
 script_bugtraq_id(6218, 6754, 6755, 6756, 6757, 6759, 6811, 6814, 6962, 7056);
 script_osvdb_id(17580, 60253, 60369, 60372);

 script_name(english:"Opera < 7.03 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is vulnerable to
various security flaws, ranging from cross-site scripting to buffer
overflows. 

To exploit them, an attacker would need to set up a rogue website,
then lure a user of this host visit it using Opera.  He would then be
able to execute arbitrary code on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/703/" );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.03 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79, 119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/26");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

 script_summary(english:"Determines the version of Opera.exe");
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}

#

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 3)
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
