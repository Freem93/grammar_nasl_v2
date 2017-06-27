#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62702);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/02/16 03:38:32 $");

  script_cve_id(
    "CVE-2012-4172",
    "CVE-2012-4173",
    "CVE-2012-4174",
    "CVE-2012-4175",
    "CVE-2012-4176",
    "CVE-2012-5273"
  );
  script_bugtraq_id(
    56187, 
    56188, 
    56190, 
    56193, 
    56194, 
    56195
  );
  script_osvdb_id(
    86537, 
    86538, 
    86539, 
    86540, 
    86541, 
    86542
  );
  script_xref(name:"CERT", value:"872545");

  script_name(english:"Shockwave Player <= 11.6.7.637 Multiple Vulnerabilities (APSB12-23)");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser plugin that is affected
by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe's Shockwave Player
that is equal to or earlier than 11.6.7.637 and is, therefore,
potentially affected by the following vulnerabilities :

  - Several unspecified errors exist that can lead to
    buffer overflow vulnerabilities and possible code
    execution. (CVE-2012-4172, CVE-2012-4173, CVE-2012-4174,
    CVE-2012-4175, CVE-2012-5273)

  - An array out-of-bounds error exists that can lead to
    code execution. (CVE-2012-4176)

A remote attacker could exploit these issues by tricking a user into
viewing a malicious Shockwave file, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-23.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave Player 11.6.8.638 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_apsb09_08.nasl");
  script_require_keys("SMB/shockwave_player");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Shockwave Player";
latest_vuln_version = "11.6.7.637"; # versions <= this version are vuln
fix = "11.6.8.638";

port = get_kb_item("SMB/transport");
installs = get_kb_list_or_exit("SMB/shockwave_player/*/path");

info = NULL;
pattern = "SMB/shockwave_player/([^/]+)/([^/]+)/path";

vuln = 0;
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
      info += '\n  Variant           : Browser Plugin (for Firefox / Netscape / Opera)';
    else if (variant == "ActiveX")
      info += '\n  Variant           : ActiveX control (for Internet Explorer)';
    info +=
      '\n  File              : ' + file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    vuln++;
  }
}

if (!info) audit(AUDIT_INST_VER_NOT_VULN, appname);

if (report_verbosity > 0)
{
  if (vuln > 1) s = "s";
  else s = "";

  report =
    '\nNessus has identified the following vulnerable instance' + s + ' of Shockwave'+
    '\nPlayer installed on the remote host :' +
    '\n' +
    info + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
