#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11578);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2003-1396");
 script_bugtraq_id(7450);
 script_osvdb_id(58496);

 script_name(english:"Opera < 7.11 Filename Extension Handling Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host has a buffer
overflow condition in the code which handles the file extensions of
the remote web pages. 

To exploit them, an attacker would need to set up a rogue website,
then lure a user of this host visit it using Opera.  He would then be
able to execute arbitrary code on this host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/347" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.11 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/06");
 script_cvs_date("$Date: 2016/11/02 14:37:07 $");
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
  (ver[0] == 6 && ver[1] >= 5) ||
  (ver[0] == 7 && ver[1] < 11)
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
