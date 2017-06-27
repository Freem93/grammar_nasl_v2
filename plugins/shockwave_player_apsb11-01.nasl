#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51936);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/04/22 23:09:44 $");

  script_cve_id(
    "CVE-2010-2587", "CVE-2010-2588", "CVE-2010-2589", "CVE-2010-4092", 
    "CVE-2010-4093", "CVE-2010-4187", "CVE-2010-4188", "CVE-2010-4189",
    "CVE-2010-4190", "CVE-2010-4191", "CVE-2010-4192", "CVE-2010-4193",
    "CVE-2010-4194", "CVE-2010-4195", "CVE-2010-4196", "CVE-2010-4306",
    "CVE-2010-4307", "CVE-2011-0555", "CVE-2011-0556", "CVE-2011-0557",
    "CVE-2011-0569");
  script_bugtraq_id(
    44617, 
    46316,
    46317,
    46318,
    46319,
    46320,
    46321,
    46324,
    46325,
    46326,
    46327,
    46328,
    46329,
    46330,
    46332,
    46333,
    46334,
    46335,
    46336,
    46338,
    46339
  );
  script_osvdb_id(
    68982,
    72507,
    72508,
    72509,
    72510,
    72511,
    72512,
    72513,
    72514,
    72515,
    72516,
    72997,
    72998,
    72999,
    73000,
    73001,
    73002,
    73003,
    73004,
    73005,
    73006
  );
  script_xref(name:"Secunia", value:"42112");

  script_name(english:"Shockwave Player < 11.5.9.620 (APSB11-01)");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser plugin that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe's Shockwave
Player that is earlier than 11.5.9.620.  Such versions are potentially
affected by the following issues :

  - Several unspecified errors exist in the 'dirapi.dll' 
    module that may allow arbitrary code execution. 
    (CVE-2010-2587, CVE-2010-2588, CVE-2010-4188)

  - An error exists in the 'dirapi.dll' module related to 
    an integer overflow and that may allow arbitrary code
    execution. (CVE-2010-2589)

  - It is reported that a use-after-free error exists in an
    unspecified compatibility component related to the 
    'Settings' window and an unloaded, unspecified library. 
    This error is reported to allow arbitrary code execution 
    when a crafted, malicious website is visited. 
    (CVE-2010-4092)

  - Unspecified errors exist that may allow arbitrary 
    code execution or memory corruption. The attack vectors
    is unspecified. (CVE-2010-4093, CVE-2010-4187, 
    CVE-2010-4190, CVE-2010-4191, CVE-2010-4192, 
    CVE-2010-4306, CVE-2011-0555)

  - An input validation error exists in the 'IML32' module
    that may allow arbitrary code execution when processing 
    global color table size of a GIF image contained in a 
    Director movie. (CVE-2010-4189)

  - An unspecified input validation error exists that may
    allow arbitrary code execution through unspecified
    vectors. (CVE-2010-4193)

  - An unspecified input validation error exists in the 
    'dirapi.dll' module that may allow arbitrary code 
    execution through unspecified vectors. (CVE-2010-4194)

  - An integer overflow error exists in the '3D Assets'
    module when parsing 3D assets containing the record
    type '0xFFFFFF45'. This error may allow arbitrary code
    execution. (CVE-2010-4196)

  - An input validation error exists in the 'DEMUX' chunks 
    parsing portion of the 'TextXtra.x32' module. This
    error may allow arbitrary code execution. 
    (CVE-2010-4195)

  - An unspecified buffer overflow error exists that may
    allow arbitrary code execution through unspecified
    vectors. (CVE-2010-4307)

  - An error exists in the 'PFR1' chunks parsing portion
    of the 'Font Xtra.x32' module. This error may allow
    arbitrary code execution. (CVE-2011-0556)

  - An unspecified integer overflow error exists that may
    allow arbitrary code execution through unspecified
    vectors.(CVE-2011-0557)

  - An error exists in the 'Font Xtra.x32' module related
    to signedness that may allow arbitrary code execution.
    (CVE-2011-0569)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-079/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-080/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-01.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.5.9.620 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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
  if (!match) exit(1, 'Unexpected format of KB key "' + install + '".');

  file = installs[install];
  variant = match[1];
  version = match[2];

  if (ver_compare(ver:version, fix:'11.5.9.620') == -1)
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
