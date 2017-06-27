#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59047);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id(
    "CVE-2012-2029",
    "CVE-2012-2030",
    "CVE-2012-2031",
    "CVE-2012-2032",
    "CVE-2012-2033"
  );
  script_bugtraq_id(53420);
  script_osvdb_id(81748, 81749, 81750, 81751, 81752);

  script_name(english:"Shockwave Player <= 11.6.4.634 Multiple Memory Corruption Vulnerabilities (APSB12-13)");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser plugin that is affected
by multiple memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe's Shockwave Player
that is 11.6.4.634 or earlier.  As such, it is potentially affected by
multiple unspecified memory corruption vulnerabilities.  

A remote attacker could exploit these issues by tricking a user into
viewing a malicious Shockwave file, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/May/71");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/May/72");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/May/73");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-13.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave Player 11.6.5.635 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_apsb09_08.nasl");
  script_require_keys("SMB/shockwave_player");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

appname = "Shockwave Player";
latest_vuln_version = "11.6.4.634"; # versions <= this version are vuln
fix = "11.6.5.635";

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

  if (ver_compare(ver:version, fix:latest_vuln_version) <= 0)
  {
    if (variant == "Plugin")
      info += '\n  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
    else if (variant == "ActiveX")
      info += '\n  - ActiveX control (for Internet Explorer) :\n';
    info += '    ' + file + ', ' + version + '\n';
  }
}

if (!info) 
  audit(AUDIT_NOT_INST, appname);

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 2) s = "s";
  else s = "";

  report =
    '\nNessus has identified the following vulnerable instance' + s + ' of Shockwave'+
    '\nPlayer installed on the remote host :' +
    '\n' +
    info +
    '\n  Fixed version : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
