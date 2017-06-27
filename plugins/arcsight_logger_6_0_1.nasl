#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81976);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-7884");
  script_bugtraq_id(73071);
  script_osvdb_id(119489, 119695, 119696);
  script_xref(name:"CERT", value:"868948");
  script_xref(name:"HP", value:"HPSBGN03249");
  script_xref(name:"HP", value:"emr_na-c04562193");
  script_xref(name:"HP", value:"SSRT101697");

  script_name(english:"HP ArcSight Logger < 6.0P1 Multiple Vulnerabilities");
  script_summary(english:"Checks the ArcSight Logger version number.");

  script_set_attribute(attribute:"synopsis", value:
"A log collection and management system on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of HP
ArcSight Logger installed on the remote host is prior to 6.0P1. It is,
therefore, affected by the following vulnerabilities :

  - An XXE injection vulnerability exists due to the
    improper verification of sources. An authenticated,
    remote attacker, using specially crafted XML data, can
    exploit this to execute scripts on the host with the
    application's level of privileges.

  - A flaw exists due to the improper validation of
    user-uploaded file names when uploading files via the
    configuration import file upload capability. An
    authenticated, remote attacker can exploit this to
    execute arbitrary PHP scripts on the server.

  - A flaw exists due to improper permissions on the Content
    Management import/export features. An authenticated,
    remote attacker can exploit this to modify the sources
    and parsers.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04562193
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd38bf6f");
  script_set_attribute(attribute:"solution", value:"Upgrade to ArcSight Logger 6.0P1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("arcsight_logger_installed_linux.nasl");
  script_require_keys("installed_sw/ArcSight Logger");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_internals.inc");
include("install_func.inc");

app = "ArcSight Logger";
port = 0;

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver = install['version'];
path = install['path'];
display_ver = install['display_version'];

fix = '6.0.0.7307.1';
display_fix = '6.0.0.7307.1 (6.0P1)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
