#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22056);
  script_version("$Revision: 1.26 $");

  script_cve_id("CVE-2006-3014", "CVE-2006-3311", "CVE-2006-3587", "CVE-2006-3588", "CVE-2006-4640");
  script_bugtraq_id(18894, 19980);
  script_osvdb_id(27113, 27507, 28732, 28733, 28734);
  script_xref(name:"CERT", value:"474593");

  script_name(english:"Flash Player Multiple Vulnerabilities (APSB06-11)");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plugin that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Flash Player on the
remote Windows host is affected by arbitrary code execution and denial
of service issues.  By convincing a user to visit a site with a
specially crafted SWF file, an attacker may be able to execute
arbitrary code on the affected host or cause the web browser to crash." );
 script_set_attribute(attribute:"see_also", value:"http://www.fortinet.com/FortiGuardCenter/advisory/FG-2006-20.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.fortinet.com/FortiGuardCenter/advisory/FG-2006-21.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb06-11.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 9.0.16.0 / 8.0.33.0 / 7.0.66.0 /
6.0.88.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/21");
 script_cvs_date("$Date: 2016/02/12 14:37:15 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/11/14");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
          iver[0] < 6 ||
          (iver[0] == 6 && iver[1] == 0 && iver[2] < 88) ||
          (iver[0] == 7 && iver[1] == 0 && iver[2] < 66) ||
          (iver[0] == 8 && iver[1] == 0 && iver[2] < 33)
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
    "Nessus has identified the following vulnerable instance(s) of Flash\n",
    "Player installed on the remote host :\n",
    "\n",
    info
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
