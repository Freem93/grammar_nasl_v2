#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97552);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id("CVE-2016-4384");
  script_bugtraq_id(93069);
  script_osvdb_id(144643);
  script_xref(name:"HP", value:"HPSBGN03648");
  script_xref(name:"HP", value:"PSRT110230");
  script_xref(name:"HP", value:"emr_na-c05278882");
  script_xref(name:"TRA", value:"TRA-2016-26");

  script_name(english:"HPE LoadRunner < 12.50 mchan.dll Packet Handling Invalid Memory Access DoS");
  script_summary(english:"Checks the version of HP LoadRunner.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote Windows host is
prior to 12.50 patch 3. It is, therefore, affected by a denial of
service vulnerability in the mchan.dll library due to improper
parsing of malformed packets. An unauthenticated, remote attacker can
exploit this, via a specially crafted request, to crash the service.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05278882
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?491a66db");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP LoadRunner version 12.50 patch 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "HP LoadRunner";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
verui = install['display_version'];
vuln = FALSE;
note = '';

fix = '12.50'; # patch 3

# below 12.50
if (ver_compare(ver:verui, fix:fix, strict:FALSE) < 0)
{
  vuln = TRUE;
}

if (!vuln)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

port = kb_smb_transport();
if (!port) port = 445;

order = make_list("Path", "Installed version", "Fixed version");
items = make_array(
  order[0], path,
  order[1], verui,
  order[2], fix + " patch 3 or later"
);
report = report_items_str(report_items:items, ordered_fields:order) + note;

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
