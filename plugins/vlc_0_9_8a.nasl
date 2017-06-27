#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35068);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-5276");
  script_bugtraq_id(32545);
  script_osvdb_id(50333);

  script_name(english:"VLC Media Player 0.9.x < 0.9.8a RealMedia Processing Remote Integer Overflow");
  script_summary(english:"Checks version of VLC");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
integer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of VLC media player 0.9 installed on the remote host is
earlier than 0.9.8a.  Such versions contain a heap-based integer
buffer overflow in the Real demuxer plugin (libreal_plugin.*').  If an
attacker can trick a user into opening a specially crafted RealMedia
(.rm) file, arbitrary code could be executed within the context of the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.trapkit.de/advisories/TKADV2008-013.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Dec/3" );
 script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/sa0811.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VLC Media Player version 0.9.8a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/09");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
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
if (ver && tolower(ver) =~ "^0\.9\.([0-7]($|[^0-9])|8$)")
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
