#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29741);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2007-4324", "CVE-2007-4768", "CVE-2007-5275", "CVE-2007-6242",
                "CVE-2007-6243", "CVE-2007-6244", "CVE-2007-6245", "CVE-2007-6246");
  script_bugtraq_id(25260, 26346, 26930, 26949, 26951, 26960, 26965, 26966, 26969);
  script_osvdb_id(
    40766,
    41475,
    41483,
    41484,
    41485,
    41486,
    41487,
    41488,
    41489,
    51567
  );

  script_name(english:"Flash Player < 7.0.73.0 / 9.0.115.0 Multiple Vulnerabilities (APSB07-20)");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plugin that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Flash Player on the
remote Windows host is affected by multiple issues, including several
which could allow for arbitrary code execution by means of a malicious
SWF file." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-20.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 9.0.115.0 / 7.0.73.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 79, 119, 264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/12/18");
 script_cvs_date("$Date: 2017/01/06 22:54:52 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");
  exit(0);
}

#

if (!get_kb_item("SMB/Flash_Player/installed")) exit(0);


# Identify vulnerable versions.
info = "";

foreach variant (make_list("Plugin", "ActiveX"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if (!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");

      ver = vers[key];
      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        if (
          (iver[0] == 7 && iver[1] == 0 && iver[2] < 73) ||
          (iver[0] == 8 && iver[1] == 0 && iver[2] <= 35) ||
          (iver[0] == 9 && iver[1] == 0 && iver[2] < 115)
        )
        {
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];
          if (variant == "Plugin")
          {
            info += '  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
          }
          else if (variant == "ActiveX")
          {
            info += '  - ActiveX control (for Internet Explorer) :\n';
          }
          info += '    ' + file + ', ' + ver + '\n';
        }
      }
    }
  }
}


if (info)
{
  report = string(
    "\n",
    "Nessus has identified the following vulnerable instance(s) of Flash\n",
    "Player installed on the remote host :\n",
    "\n",
    info
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
