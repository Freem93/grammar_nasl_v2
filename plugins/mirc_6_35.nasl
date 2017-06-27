#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34471);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-4449");
  script_bugtraq_id(31552);
  script_xref(name:"EDB-ID", value:"6654");
  script_xref(name:"EDB-ID", value:"6666");
  script_xref(name:"OSVDB", value:"48752");

  script_name(english:"mIRC PRIVMSG Handling Remote Buffer Overflow");
  script_summary(english:"Checks version number of mIRC");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a chat client that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of mIRC installed on the remote host is earlier than 6.35
and thus reportedly prone to a buffer overflow attack that can be
triggered by a long hostname in a PRIVMSG message.  If an attacker can
trick a user into connecting to a malicious IRC server (perhaps via
JavaScript in an HTML document), this issue could be leveraged to
execute arbitrary code on the remote host subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mirc.com/news.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to mIRC 6.35 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'mIRC PRIVMSG Handling Stack Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/22");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("mirc_installed.nasl");
  script_require_keys("SMB/mIRC/Version");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/mIRC/Version_UI");
version = get_kb_item("SMB/mIRC/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 6 || 
  (ver[0] == 6 && ver[1] < 35)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "mIRC ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
