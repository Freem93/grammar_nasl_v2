#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56734);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/06/14 20:29:54 $");

  script_cve_id(
    "CVE-2011-2446",
    "CVE-2011-2447", 
    "CVE-2011-2448", 
    "CVE-2011-2449"
  );
  script_bugtraq_id(50581, 50583, 50584, 50586);
  script_osvdb_id(76966, 76967, 76968, 76969);

  script_name(english:"Shockwave Player <= 11.6.1.629 Multiple Memory Corruption Vulnerabilities (APSB11-27)");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser plugin that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe's Shockwave
Player that is 11.6.1.629 or earlier.  As such, it is potentially
affected by multiple memory corruption vulnerabilities. 

A remote attacker could exploit these issues by tricking a user into
viewing a malicious Shockwave file, resulting in arbitrary code
execution.");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-27.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.6.3.633 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_apsb09_08.nasl");
  script_require_keys("SMB/shockwave_player");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("SMB/transport");
installs = get_kb_list_or_exit("SMB/shockwave_player/*/path");

info = NULL;
pattern = "SMB/shockwave_player/([^/]+)/([^/]+)/path";

foreach install (keys(installs))
{
  match = eregmatch(string:install, pattern:pattern);
  if (!match) exit(1, "Unexpected format of KB key '" + install + "'.");

  file = installs[install];
  variant = match[1];
  version = match[2];

  # nb: APSB11-27 says version 11.6.1.629 and earlier are affected.
  if (ver_compare(ver:version, fix:"11.6.1.629") <= 0)
  {
    if (variant == "Plugin")
      info += '\n  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
    else if (variant == "ActiveX")
      info += '\n  - ActiveX control (for Internet Explorer) :\n';
    info += '    ' + file + ', ' + version + '\n';
  }
}

if (!info) exit(0, "No vulnerable installs of Shockwave Player were found.");

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 2) s = "s";
  else s = "";

  report =
    '\nNessus has identified the following vulnerable instance' + s + ' of Shockwave'+
    '\nPlayer installed on the remote host :' +
    '\n' +
    info;
  security_hole(port:port, extra:report);
}
else security_hole(port);
