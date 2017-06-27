#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34730);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-5032", "CVE-2008-5036");
  script_bugtraq_id(32125, 36403);
  script_osvdb_id(49808, 49809);
  script_xref(name:"EDB-ID", value:"18548");

  script_name(english:"VLC Media Player 0.5.0 to 0.9.5 Stack-Based Buffer Overflows");
  script_summary(english:"Checks version of VLC Media Player");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple buffer overflow vulnerabilities." );

  script_set_attribute(attribute:"description", value:
"A version of VLC between 0.5.0 and 0.9.5 is installed on the remote
host.  Such versions are affected by the following vulnerabilities :

  - RealText subtitle file (modules\demux\subtitle.c)
    processing is susceptible to a buffer overflow caused 
    by user-supplied data from a malicious subtitle file 
    being copied into static buffers without proper 
    validation.

  - CUE image file (modules\access\vcd\cdrom.c)
    processing is susceptible to a stack-based buffer 
    overflow because data supplied by the CUE file is 
    supplied as an array index without proper validation.

An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by tricking a user into opening a specially
crafted video file using the affected application." );

  script_set_attribute(attribute:"see_also", value:"http://www.trapkit.de/advisories/TKADV2008-012.txt" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498111/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498112/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/security/sa0810.html" );
  script_set_attribute(attribute:"see_also", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/1140" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 0.9.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VLC Media Player RealText Subtitle Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/10");
 script_cvs_date("$Date: 2016/11/29 20:13:36 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include("global_settings.inc");

ver = get_kb_item("SMB/VLC/Version");
if (ver && ver =~ "^0\.([5-8]\.|9\.[0-5]($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "VLC Media Player version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
