#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99200);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/05 19:56:47 $");

  script_osvdb_id(153848);
  script_name(english:"Oracle VM VirtualBox 5.0.x < 5.0.34 / 5.1.x < 5.1.16 Shared Folder Implementation Information Disclosure");
  script_summary(english:"Performs a version check of VirtualBox.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox installed on the remote host is
5.0.x prior to 5.0.34 or 5.1.x prior to 5.1.16. It is, therefore,
affected by an information disclosure vulnerability within the shared
folder implementation, specifically in the vbsfPathCheckRootEscape()
function, that permits cooperating guests that have write access to
the same shared folder to gain access to the file system of the Linux
host. An authenticated attacker within a guest VM can exploit this to
read arbitrary files on the host. However, exploitation requires that
the shared folder is not more than nine levels away from the file
system root.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://bugs.chromium.org/p/project-zero/issues/detail?id=1037
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?a61fdb8e");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.0.34 / 5.1.16 or later");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app  = NULL;
apps = make_list('Oracle VM VirtualBox', 'VirtualBox');

foreach app (apps)
{
  if (get_install_count(app_name:app)) break;
  else app = NULL;
}

if (isnull(app)) audit(AUDIT_NOT_INST, 'Oracle VM VirtualBox');

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];

# Affected :
# 5.0.x < 5.0.34 / 5.1.x < 5.1.16
if  (ver =~ '^5\\.0' && ver_compare(ver:ver, fix:'5.0.34', strict:FALSE) < 0) fix = '5.0.34';
else if  (ver =~ '^5\\.1' && ver_compare(ver:ver, fix:'5.1.16', strict:FALSE) < 0) fix = '5.1.16';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
exit(0);
