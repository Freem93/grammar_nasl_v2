#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65690);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

  script_cve_id("CVE-2013-0169", "CVE-2013-1762");
  script_bugtraq_id(57778, 58277);
  script_osvdb_id(89848, 90841);

  script_name(english:"stunnel 4.21 - 4.54 Multiple Vulnerabilities");
  script_summary(english:"Checks version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of stunnel installed on the remote host is a version
after 4.21 and prior to 4.55. It is, therefore, affected by the
following vulnerabilities :

  - The bundled version of OpenSSL contains an error related
    to CBC-mode and timing that allows an attacker to
    recover plaintext from encrypted communications.
    (CVE-2013-0169)

  - A buffer overflow condition exists related to NTLM
    authentication. Note this issue does not affect 32-bit
    builds.(CVE-2013-1762)");
  script_set_attribute(attribute:"see_also", value:"http://stunnel.org/?page=sdf_ChangeLog");
  # http://www.stunnel.org/pipermail/stunnel-announce/2013-March/000072.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0bf4f9d5");
  script_set_attribute(attribute:"see_also", value:"https://www.stunnel.org/CVE-2013-1762.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to stunnel version 4.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("stunnel_installed.nasl");
  script_require_keys("installed_sw/stunnel");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'stunnel';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

# Affected 4.21 >= stunnel < 4.55
if (version =~ "^4\.(2[1-9]|[34][0-9]|5[0-4])($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.55\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
