#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32394);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

  script_cve_id("CVE-2008-2400");
  script_bugtraq_id(29285);
  script_osvdb_id(45354);
  script_xref(name:"Secunia", value:"30297");

  script_name(english:"stunnel < 4.23 Local Privilege Escalation");
  script_summary(english:"Checks version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"A remote Windows host contains a program that is affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running stunnel, an application for encrypting
arbitrary network connections with SSL.

The version of stunnel installed on the remote host, when running as a
service, allows a local user to gain LocalSystem privileges due to an
unspecified error.");
  script_set_attribute(attribute:"see_also", value:"http://www.stunnel.org/news/");
  # http://web.archive.org/web/20080608095943/http://stunnel.mirt.net/pipermail/stunnel-announce/2008-May/000034.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1def20e3");
  script_set_attribute(attribute:"solution", value:"Upgrade to stunnel version 4.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("stunnel_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("installed_sw/stunnel");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Make sure the stunnel service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item_or_exit("SMB/svcs");
  if ("stunnel" >!< services) exit(0, "The stunnel service was not found on the remote host.");
}

app = 'stunnel';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

# Affected < 4.23
if (
  version =~ "^[0-3]($|[^0-9])" ||
  version =~ "^4\.(0?[0-9]|1[0-9]|2[0-2])($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.23\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
