#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14249);
 script_version("$Revision: 1.15 $");

 script_bugtraq_id(7430);
 script_osvdb_id(60491);

 script_name(english:"Opera < 7.20 news URL Handling DoS");

 script_set_attribute(attribute:"synopsis", value:
"A browser installed on the remote host is vulnerable to a denial of 
service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly crashes
when processing a 'news:' URL of excessive length, that may result in
a denial of service.  It has been reported that this issue will
trigger a condition that will prevent Opera from functioning until the
program has been reinstalled." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.20 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_cvs_date("$Date: 2012/06/19 21:49:20 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();
 
 script_summary(english:"Determines the version of Opera.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
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
  (ver[0] == 7 && ver[1] < 20)
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
