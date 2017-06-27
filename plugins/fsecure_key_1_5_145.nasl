#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76788);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/25 17:35:47 $");

  script_bugtraq_id(68552);
  script_osvdb_id(106795);

  script_name(english:"F-Secure Key Plaintext Information Disclosure");
  script_summary(english:"Checks the version of fskey.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of F-Secure Key prior to
1.5.145. It is, therefore, affected by an unspecified error that could
allow a local attacker to dump the contents of memory and obtain
sensitive plaintext information.");
  script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/en/web/labs_global/fsc-2014-3");
  script_set_attribute(attribute:"solution", value:"Upgrade to 1.5.145 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:f-secure:key");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_dependencies("fsecure_key_installed.nbin");
  script_require_keys("installed_sw/F-Secure Key");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = 'F-Secure Key';
get_install_count(app_name:app_name, exit_if_zero:TRUE);

# Only 1 install is possible.
install = get_installs(app_name:app_name);
if (install[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, app_name);
install = install[1][0];

version = install['version'];
install_path = install['path'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);

fixed_version = '1.5.145';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = '445';

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);
