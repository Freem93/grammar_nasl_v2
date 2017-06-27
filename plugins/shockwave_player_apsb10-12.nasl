#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46329);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id(
    "CVE-2010-0127",
    "CVE-2010-0128",
    "CVE-2010-0129",
    "CVE-2010-0130",
    "CVE-2010-0986",
    "CVE-2010-0987",
    "CVE-2010-1280",
    "CVE-2010-1281",
    "CVE-2010-1282",
    "CVE-2010-1283",
    "CVE-2010-1284",
    "CVE-2010-1286",
    "CVE-2010-1287",
    "CVE-2010-1288",
    "CVE-2010-1289",
    "CVE-2010-1290",
    "CVE-2010-1291",
    "CVE-2010-1292"
  );
  script_bugtraq_id(
    40076,
    40077,
    40078,
    40079,
    40081,
    40082,
    40083,
    40084,
    40085,
    40086,
    40087,
    40088,
    40089,
    40090,
    40091,
    40093,
    40094,
    40096
  );
  script_osvdb_id(
    64640,
    64641,
    64642,
    64643,
    64644,
    64645,
    64646,
    64647,
    64648,
    64649,
    64650,
    64651,
    64652,
    64653,
    64654,
    64655,
    64656,
    64657
  );
  script_xref(name:"Secunia", value:"38751");

  script_name(english:"Shockwave Player < 11.5.7.609 Multiple Vulnerabilities (APSB10-12)");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser plugin that is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe's Shockwave Player
that is earlier than 11.5.7.609.  Such versions are affected by the
following issues :

  - Processing specially crafted FFFFFF45h Shockwave
    3D blocks can result in memory corruption.
    (CVE-2010-0127, CVE-2010-1283)

  - A signedness error that can lead to memory corruption
    when processing specially crafted Director files.
    (CVE-2010-0128)

  - An array indexing error that can lead to memory
    corruption when processing specially crafted
    Director files. (CVE-2010-0129)

  - An integer overflow vulnerability that can lead to
    memory corruption when processing specially
    crafted Director files. (CVE-2010-0130)

  - An unspecified error when processing asset entries
    in Director files can lead to memory corruption.
    (CVE-2010-0986)

  - A boundary error when processing embedded fonts
    from a Directory file can lead to memory corruption.
    (CVE-2010-0987)

  - An unspecified error when processing Director files
    can result in memory corruption. (CVE-2010-1280)

  - Several unspecified memory corruption vulnerabilities.
    (CVE-2010-1281, CVE-2010-1282, CVE-2010-1284,
    CVE-2010-1286, CVE-2010-1287, CVE-2010-1288,
    CVE-2010-1289, CVE-2010-1290, CVE-2010-1291,
    CVE-2010-1292)"
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-17/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-19/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-20/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-22/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-34/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-50/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-087/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-088/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-089/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19865c37");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/136");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/137");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/138");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4937.php");
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/adobe-director-invalid-read");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-12.html");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe Shockwave 11.5.7.609 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_apsb09_08.nasl");
  script_require_keys("SMB/shockwave_player");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


port = kb_smb_transport();
installs = get_kb_list('SMB/shockwave_player/*/path');
if (isnull(installs))
  exit(0, 'Shockwave Player was not detected on the remote host.');

info = NULL;
pattern = 'SMB/shockwave_player/([^/]+)/([^/]+)/path';

foreach install (keys(installs))
{
  match = eregmatch(string:install, pattern:pattern);
  if (!match) exit(1, 'Unexpected format of KB key "'+install+'".');

  file = installs[install];
  variant = match[1];
  version = match[2];
  ver = split(version, sep:'.', keep:FALSE);
  for (i = 0; i < max_index(ver); i++)
     ver[i] = int(ver[i]);

  if (
    ver[0] < 11 ||
    (
      ver[0] == 11 &&
      (
        ver[1] < 5 ||
        (
          ver[1] == 5 &&
          (
            ver[2] < 7 ||
            (ver[2] == 7 && ver[3] < 609)
          )
        )
      )
    )
  )
  {
    if (variant == "Plugin")
    {
      info += '\n  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
    }
    else if (variant == "ActiveX")
    {
      info += '\n  - ActiveX control (for Internet Explorer) :\n';
    }
    info += '    ' + file + ', ' + version + '\n';
  }
}

if (!info) exit(0, "No vulnerable installs of Shockwave Player were found.");

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 2) s = "s";
  else s = "";

  report =
    '\nNessus has identified the following vulnerable instance'+s+' of Shockwave'+
    '\nPlayer installed on the remote host :\n'+
    info;
  security_hole(port:port, extra:report);
}
else security_hole(port:port);

