#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83730);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

  script_cve_id("CVE-2015-3644");
  script_bugtraq_id(74659);
  script_osvdb_id(122182);
  script_xref(name:"IAVB", value:"2015-B-0063");

  script_name(english:"stunnel < 5.14 Authentication Bypass Vulnerability");
  script_summary(english:"Checks the version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of stunnel installed on the remote host is prior to
version 5.14. It is, therefore, affected by a vulnerability related
to the handling of authentication failures that involve the 'redirect'
option. In this case, only the initial connection is forwarded to the
hosts specified with 'redirect'; however, subsequent connections
established with reused SSL/TLS sessions are forwarded to the hosts
specified with 'connect' as if they were already successfully
authenticated. A remote attacker can exploit this vulnerability to
bypass authentication mechanisms.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.stunnel.org/CVE-2015-3644.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to stunnel 5.14 or later. Alternatively, remove the 'redirect'
option from the configuration file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

# Affected: 5.00 thru 5.13
if (version =~ "^5\.(0[0-9]|1[0-3])($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.14' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
