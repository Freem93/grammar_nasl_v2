#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(57941);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/06/14 20:24:39 $");

  script_bugtraq_id(
    51999,
    52000,
    52001,
    52002,
    52003,
    52004,
    52005,
    52006,
    52007
  );
  script_cve_id(
    "CVE-2012-0757",
    "CVE-2012-0758",
    "CVE-2012-0759",
    "CVE-2012-0760",
    "CVE-2012-0761",
    "CVE-2012-0762",
    "CVE-2012-0763",
    "CVE-2012-0764",
    "CVE-2012-0766"
  );
  script_osvdb_id(
    79237,
    79238,
    79239,
    79240,
    79241,
    79242,
    79243,
    79244,
    79245
  );

  script_name(english:"Shockwave Player <= 11.6.3.633 Multiple Code Execution Vulnerabilities (APSB12-02)");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser plugin that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe's Shockwave
Player that is 11.6.3.633 or earlier.  As such, it is potentially
affected by multiple code execution vulnerabilities. 

  - Multiple memory corruption issues exist related to the
    Shockwave 3D Asset that could lead to code execution.
    (CVE-2012-0757, CVE-2012-0760, CVE-2012-0761,
    CVE-2012-0762, CVE-2012-0763, CVE-2012-0764,
    CVE-2012-0766)

  - An unspecified heap-based buffer overflow exists that
    could lead to code execution. (CVE-2012-0758)

  - An unspecified memory corruption vulnerability exists
    that could lead to code execution. (CVE-2012-0759)

A remote attacker could exploit these issues by tricking a user into
viewing a malicious Shockwave file, resulting in arbitrary code
execution.");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-02.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.6.4.634 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

  # nb: APSB12-02 says version 11.6.3.633 and earlier are affected.
  if (ver_compare(ver:version, fix:"11.6.3.633") <= 0)
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
