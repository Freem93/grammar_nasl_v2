#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34948);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1120");
  script_bugtraq_id(28027);
  script_xref(name:"OSVDB", value:"42889");
  script_xref(name:"Secunia", value:"29138");
  
  script_name(english:"ICQ < 6 Build 6059 Message Processing Format String");
  script_summary(english:"Checks ICQ version");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a chat client that is affected by a remote
format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of ICQ installed on the remote host is earlier than 6
Build 6059.  Such versions reportedly are affected by a format string
vulnerability in the embedded Internet Explorer component triggered
when processing HTML messages with a format string specifier such as
'%020000000p'.  If a remote attacker can trick a user on the remote
host into viewing a message with the affecting application, he may be
able to leverage this issue to crash the affected application or to
execute arbitrary code on the remote host subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://keksa.de/?q=icqstory" );
 script_set_attribute(attribute:"see_also", value:"http://board.raidrush.ws/showthread.php?t=386983" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5251565e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ICQ 6 build 6059 (6.0.0.6059) or later as that reportedly
addresses the issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(134);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/24");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("icq_installed.nasl");
  script_require_keys("SMB/ICQ/Version");

  exit(0);
}


include("global_settings.inc");


product = get_kb_item("SMB/ICQ/Product");
if (isnull(product)) product = "ICQ";

version = get_kb_item("SMB/ICQ/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 6 || 
  (ver[0] == 6 && ver[1] == 0 && ver[2] == 0 && ver[3] < 6059)
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      product, " ", version, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
