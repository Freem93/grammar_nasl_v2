#
# (C) Tenable Network Security, Inc.
#

# Ref: 
#
# Date: Mon, 09 Jun 2003 12:19:40 +0900
# From: ":: Operash ::" <nesumin@softhome.net>
# To: bugtraq@securityfocus.com
# Subject: [SmartFTP] Two Buffer Overflow Vulnerabilities
#

include("compat.inc");

if(description)
{
 script_id(11709);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2003-1319");
 script_bugtraq_id(7858, 7861);
 script_xref(name:"OSVDB", value:"35767");
 script_xref(name:"OSVDB", value:"35768");

 script_name(english:"SmartFTP Multiple Command Response Overflow");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host through a
remote FTP client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SmartFTP - an FTP client.

There is a flaw in the remote version of this software that could allow an 
attacker to execute arbitrary code on this host.

To exploit it, an attacker would need to set up a rogue FTP server and have 
a user on this host connect to it." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.976.x or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/09");
 script_cvs_date("$Date: 2011/12/16 23:13:20 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();
 
 script_summary(english:"Determines the presence of SmartFTP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 
 script_dependencies("smartftp_detect.nasl");
 script_require_keys("SMB/SmartFTP/Version");

 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");

version = get_kb_item_or_exit('SMB/FTP/Version');
install_path = get_kb_item('SMB/SmartFTP/Path');

if (ver_compare(ver:version, fix:'1.1.0.976') == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.1.0.976\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since SmartFTP "+version+" is installed.");
