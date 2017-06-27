#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43068);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    'CVE-2009-3794',
    'CVE-2009-3796',
    'CVE-2009-3797',
    'CVE-2009-3798',
    'CVE-2009-3799',
    'CVE-2009-3800',
    'CVE-2009-3951'
  );
  script_bugtraq_id(37266, 37267, 37269, 37270, 37272, 37273, 37275);
  script_osvdb_id(60885, 60886, 60887, 60888, 60889, 60890, 60891);
  script_xref(name:"Secunia", value:"37584");

  script_name(english:"Flash Player < 9.0.260 / 10.0.42.34 Multiple Vulnerabilities (APSB09-19)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plug-in that is affected
by multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Flash Player that
is earlier than 9.0.260 or 10.0.42.34.  Such versions are potentially 
affected by multiple vulnerabilities :

  - A vulnerability in the parsing of JPEG data could lead
    to code execution. (CVE-2009-3794)

  - A data injection vulnerability could lead to code
    execution. (CVE-2009-3796)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2009-3797)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2009-3798)

  - An integer overflow vulnerability could lead to code
    execution. (CVE-2009-3799) 

  - Multiple crash vulnerabilities could lead to code
    execution. (CVE-2009-3800)

  - A Windows-only local file name access vulnerability
    could lead to information disclosure. (CVE-2009-3591)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-19.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe Flash Player 9.0.260, 10.0.42.34 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 189, 200, 399);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/12/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/09"
  );
 script_cvs_date("$Date: 2016/12/08 20:31:54 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");
  exit(0);
}

if (!get_kb_item("SMB/Flash_Player/installed")) exit(1, "The 'SMB/Flash_Player/installed' KB item is missing.");

include("global_settings.inc");

info = NULL;

foreach variant (make_list("Plugin", "ActiveX"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if(!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      ver = vers[key];
      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for(i=0;i<max_index(iver);i++)
          iver[i] = int(iver[i]);
        if (iver[0] < 9 ||
          (
            (iver[0] == 9 && iver[1] == 0 && iver[2] < 260) 
              ||
            (
              iver[0] == 10 && iver[1] == 0 &&
              (
                iver[2] < 42 ||
                (iver[2] == 42 && iver[3] < 34)
              )
            )
          )
        )
        {
          num = key - ("SMB/Flash_Player/"+variant+"/Version/");
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];
          if (variant == "Plugin")
          {
            info += '  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
          }
          else if (variant == "ActiveX")
          {
            info += '  - ActiveX control (for Internet Explorer) :\n';
          }
          info += '    ' + file + ', '+ ver + '\n';
        }
      }
    }
  }
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 2)
      inst = "s";
    else
      inst = "";

    report = 
      '\n' +
      'Nessus has identified the following vulnerable instance' + inst + ' of Flash\n' +
      'Player installed on the remote host :\n' +
      '\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
