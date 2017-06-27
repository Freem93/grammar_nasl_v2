#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80832);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2014-9093");
  script_bugtraq_id(71313);
  script_osvdb_id(115069);

  script_name(english:"LibreOffice < 4.2.8 / 4.3.5 RTF File Handling Code Execution");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an invalid
memory write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Windows host is
prior to 4.2.7 or 4.3.x prior to 4.3.5. It is, therefore, affected by
an invalid memory write vulnerability. An attacker, using a specially
crafted Rich Text Format (RTF) file, can exploit this to cause a
denial of service or possibly execute arbitrary code.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 4.2.8 (4.2.8.2), 4.3.5 (4.3.5.2) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"https://bugs.freedesktop.org/show_bug.cgi?id=86449");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "LibreOffice";

get_kb_item_or_exit("SMB/Registry/Enumerated");

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version    = install['version'];
version_ui = install['display_version'];
path       = install['path'];

if (
  # < 4.x
  version =~ "^[0-3]($|[^0-9])" ||
  # 4.2.x < 4.2.8
  version =~ "^(4\.[0-1]|4\.2\.[0-7])($|[^0-9])" ||
  # 4.3.x < 4.3.5
  version =~ "^4\.3\.[0-4]($|[^0-9])" ||
  # 4.3.5 Release is 4.3.5.2
  version =~ "^4\.3\.5\.[01]($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.2.8 (4.2.8.2) / 4.3.5 (4.3.5.2)' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui, path);
