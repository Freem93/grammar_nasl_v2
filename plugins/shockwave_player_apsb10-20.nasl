#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48436);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/11/14 18:42:59 $");
  
  script_cve_id("CVE-2010-2863", "CVE-2010-2864", "CVE-2010-2865", "CVE-2010-2866", "CVE-2010-2867",
                "CVE-2010-2868", "CVE-2010-2869", "CVE-2010-2870", "CVE-2010-2871", "CVE-2010-2872",
                "CVE-2010-2873", "CVE-2010-2874", "CVE-2010-2875", "CVE-2010-2876", "CVE-2010-2877",
                "CVE-2010-2878", "CVE-2010-2879", "CVE-2010-2880", "CVE-2010-2881", "CVE-2010-2882");
  script_bugtraq_id(42664, 42665, 42666, 42667, 42668, 42669, 42670, 42671, 42672, 42673,
                    42674, 42675, 42676, 42677, 42678, 42679, 42680, 42682, 42683, 42684);
  script_osvdb_id(
    67422,
    67423,
    67424,
    67425,
    67426,
    67427,
    67428,
    67429,
    67430,
    67431,
    67432,
    67433,
    67434,
    67435,
    67436,
    67437,
    67438,
    67439,
    67440,
    67441
  );
  script_xref(name:"Secunia", value:"41065");

  script_name(english:"Shockwave Player < 11.5.8.612");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser plugin that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe's Shockwave Player
that is earlier than 11.5.8.612.  Such versions are potentially
affected by the following issues :

  - Multiple memory corruption issues exist that could lead 
    to arbitrary code execution. (CVE-2010-2863, 
    CVE-2010-2864, CVE-2010-2866, CVE-2010-2869, 
    CVE-2010-2870, CVE-2010-2871, CVE-2010-2872, 
    CVE-2010-2873, CVE-2010-2873, CVE-2010-2874, 
    CVE-2010-2875, CVE-2010-2876, CVE-2010-2877, 
    CVE-2010-2878, CVE-2010-2880, CVE-2010-2881, 
    CVE-2010-2882)

  - A pointer offset vulnerability exists that could lead to
    code execution. (CVE-2010-2867)

  - Multiple unspecified denial of service issues exist. 
    (CVE-2010-2865, CVE-2010-2868)

  - An integer overflow vulnerability exists that could lead
    to lead to code execution. (CVE-2010-2879)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-20.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.5.8.612 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_apsb09_08.nasl");
  script_require_keys("SMB/shockwave_player");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

port = kb_smb_transport();
installs = get_kb_list('SMB/shockwave_player/*/path');
if (isnull(installs)) exit(0, 'Shockwave Player was not detected on the remote host.');

info = NULL;
pattern = 'SMB/shockwave_player/([^/]+)/([^/]+)/path';

foreach install (keys(installs))
{
  match = eregmatch(string:install, pattern:pattern);
  if (!match) exit(1, 'Unexpected format of KB key "'+install+'".');

  file = installs[install];
  variant = match[1];
  version = match[2];

  if (ver_compare(ver:version, fix:'11.5.8.612') == -1)
  {
    if (variant == 'Plugin')
      info += '\n  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
    else if (variant == 'ActiveX')
      info += '\n  - ActiveX control (for Internet Explorer) :\n';
    info += '    ' + file + ', ' + version + '\n';
  }
}

if (!info) exit(0, 'No vulnerable installs of Shockwave Player were found.');

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
else security_hole(port);
