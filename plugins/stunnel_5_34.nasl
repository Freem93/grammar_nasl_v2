#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92557);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/28 13:53:41 $");

  script_osvdb_id(141677);

  script_name(english:"stunnel 4.46 < 5.34 Improper Level 4 Peer Certificate Validation Security Bypass");
  script_summary(english:"Checks the version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of stunnel installed on the remote host is 4.46 or later
but prior to 5.34. It is, therefore, affected by a security bypass
vulnerability related to the validation of level 4 peer certificates.
An unauthenticated, remote attacker can exploit this to have an impact
on confidentiality, integrity, and/or availability. No other details
are available.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.stunnel.org/sdf_ChangeLog.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to stunnel version 5.34 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# Affected: 4.46 thru 5.33
if (
  version =~ "^4\.(4[6-9]|5[0-9])($|[^[0-9])" ||
  version =~ "^5\.([0-2][0-9]|3[0-3])($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.34' +
   '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
