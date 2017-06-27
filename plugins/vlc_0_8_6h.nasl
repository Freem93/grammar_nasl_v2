#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33278);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950", "CVE-2007-6284");
  script_bugtraq_id(27248, 29292);
  script_osvdb_id(40194, 45382, 45383, 45384);

  script_name(english:"VLC Media Player < 0.8.6h Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by
several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of VLC Media Player installed on the remote host
reportedly includes versions of GnuTLS, libgcrypt, and libxml2 that
are affected by various denial of service and buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc/NEWS" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VLC Media Player version 0.8.6h or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189, 287, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/30");
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
if (ver && tolower(ver) =~ "^0\.([0-7]\.|8\.([0-5]|6($|[a-g])))")
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
