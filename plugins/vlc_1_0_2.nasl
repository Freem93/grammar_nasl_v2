#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41626);
  script_version("$Revision: 1.8 $");

  script_bugtraq_id(36439);
  script_osvdb_id(58215, 58216, 58217);
  script_xref(name:"Secunia", value:"36762");

  script_name(english:"VLC Media Player < 1.0.2 Multiple Remote Buffer Overflows");
  script_summary(english:"Checks version of VLC");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple remote buffer overflow vulnerabilities."  );

  script_set_attribute( attribute:"description", value:
"The version of VLC media player installed on the remote host is
earlier than 1.0.2.  Such versions are vulnerable to a stack overflow
when parsing MP4, ASF, or AVI files with an overly deep box structure.
If an attacker can trick a user into opening a specially crafted MP4,
ASF, or AVI file with the affected application, arbitrary code could
be executed subject to the user's privileges."  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa0901.html"
  );
  # http://git.videolan.org/?p=vlc.git;a=commit;h=dfe7084e8cc64e9b7a87cd37065b59cba2064823
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78382b17"
  );
  # http://git.videolan.org/?p=vlc.git;a=commit;h=861e374d03e6c60c7d3c98428c632fe3b9e371b2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4c3b223"
  );
  # http://git.videolan.org/?p=vlc.git;a=commit;h=c5b02d011b8c634d041167f4d2936b55eca4d18d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82f87f14"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.0.2 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/17"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/25"
  );
 script_cvs_date("$Date: 2014/06/06 20:52:31 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include("global_settings.inc");

ver = get_kb_item("SMB/VLC/Version");
if (isnull(ver)) exit(1, "The 'SMB/VLC/Version' KB key is missing.");

if (tolower(ver) =~ "^(0\.|1\.0\.[01]($|[^0-9]))")
{
  if (report_verbosity > 0)
  { 
    report = string(
      "\n",
      "VLC Media Player version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+ver+" is installed.");
