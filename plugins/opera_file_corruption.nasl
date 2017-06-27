#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14246);
 script_version("$Revision: 1.16 $");

 script_bugtraq_id(9279);
 script_osvdb_id(3017);

 script_name(english:"Opera < 7.23 File Download Encoded Traversal Arbitrary File Deletion");

 script_set_attribute(attribute:"synopsis", value:
"Files could be overwritten on the remote host." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host contains a file 
corruption vulnerability.  This issue is exposed when a user is 
presented with a file dialog, which will cause the creation of a 
temporary file.  It is possible to specify a relative path to another 
file on the system using directory traversal sequences when the
download dialog is displayed.  If the client user has write
permissions to the attacker-specified file, it will be corrupted. 

This could be exploited to delete sensitive files on the systems." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.23 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/13");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

 script_summary(english:"Determines the version of Opera.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
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
  (ver[0] == 7 && ver[1] < 23)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
