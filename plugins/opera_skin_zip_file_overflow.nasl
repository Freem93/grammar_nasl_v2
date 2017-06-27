#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14250);
 script_version("$Revision: 1.15 $");

 script_bugtraq_id(9089);
 script_osvdb_id(2854);

 script_name(english:"Opera < 7.23 Zip File Processing Crafted File Handling Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arrbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The version of Opera on the remote host is vulnerable to a security
weakness. 

A problem has been identified in the handling of zipped skin files by
Opera.  Because of this, it may be possible for an attacker to gain
unauthorized access to a system using the vulnerable browser." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.23 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/22");
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
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
