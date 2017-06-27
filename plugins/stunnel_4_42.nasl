#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56090);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

  script_cve_id("CVE-2011-2940");
  script_bugtraq_id(49254);
  script_osvdb_id(74600);

  script_name(english:"stunnel 4.4x < 4.42 Unspecified Memory Corruption");
  script_summary(english:"Checks version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of stunnel 4.4x installed on the remote host is a version
prior to 4.42. It is, therefore, affected by a memory corruption
vulnerability that allows a remote attacker to cause a denial of
service condition or execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://stunnel.org/?page=sdf_ChangeLog");
  # http://www.stunnel.org/pipermail/stunnel-announce/2011-August/000059.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33c9ea22");
  script_set_attribute(attribute:"solution", value:"Upgrade to stunnel version 4.42 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

fix = "4.42";

# Affected 4.40 and 4.41
if (version =~ "^4\.4[01]($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
