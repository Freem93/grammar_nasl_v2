#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17362);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2004-1465");
  script_bugtraq_id(11092);
  script_osvdb_id(9511);

  script_name(english:"WinZip <= 9.0 Multiple Unspecified Overflows");
  script_summary(english:"Checks the version of WinZip.");

  script_set_attribute(attribute:'synopsis', value:
"The remote host has an application that is affected by multiple buffer
overflow vulnerabilities.");
  script_set_attribute(attribute:'description', value:
"The remote host is using a version of WinZip that is prior to 9.0-SR1.
It is, therefore, affected by several buffer overflow flaws that can
allow an attacker to execute arbitrary code on the host by convincing
a user to open a malformed archive file.");
  script_set_attribute(attribute:'solution', value:"Upgrade to WinZip 9.0-SR1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:'see_also', value:"http://www.winzip.com/wz90sr1.htm");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("winzip_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/WinZip");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "WinZip";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver      = install['version'];
path     = install['path'];
disp_ver = install['display_version'];

port = get_kb_item('SMB/transport');
if (!port) port = 445;

# Version 9.0.0 SR-1 is version 18.0.6224.0
if ( ver_compare(ver:ver, fix:'18.0.6224.0', strict:FALSE) == -1 )
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + disp_ver +
      '\n  Fixed version     : 9.0-SR1' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, disp_ver, path);
