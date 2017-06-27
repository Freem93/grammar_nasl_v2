#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44596);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2010-0186", "CVE-2010-0187");
  script_bugtraq_id(38198, 38200);
  script_osvdb_id(62300, 62370);
  script_xref(name:"Secunia", value:"38547");

  script_name(english:"Flash Player < 10.0.45.2 Multiple Vulnerabilities (APSB10-06)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plug-in that is affected
by multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Flash Player that
is earlier than 10.0.45.2.  Such versions are potentially affected by
multiple vulnerabilities :

  - An issue that could subvert the domain sandbox and make
    unauthorized cross-domain requests. (CVE-2010-0186)

  - An unspecified denial of service. (CVE-2010-0187)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.adobe.com/support/security/bulletins/apsb10-06.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Adobe Flash Player 10.0.45.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/12");
 script_cvs_date("$Date: 2016/05/05 16:01:14 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");
  exit(0);
}

if (!get_kb_item("SMB/Flash_Player/installed")) exit(1, "The 'SMB/Flash_Player/installed' KB item is missing.");

include("global_settings.inc");

info = '';

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
        if (
          (
            iver[0] == 10 && iver[1] == 0 &&
            (
              iver[2] < 45 ||
              (iver[2] == 45 && iver[3] < 2)
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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
