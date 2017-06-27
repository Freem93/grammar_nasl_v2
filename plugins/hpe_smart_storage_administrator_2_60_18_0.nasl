#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97859);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/24 14:02:38 $");

  script_cve_id("CVE-2016-8523");
  script_bugtraq_id(95868);
  script_osvdb_id(151151);
  script_xref(name:"HP", value:"emr_na-c05382349");
  script_xref(name:"IAVA", value:"2017-A-0031");
  script_xref(name:"HP", value:"HPESBMU03701");
  script_xref(name:"EDB-ID", value:"41297");

  script_name(english:"HPE Smart Storage Administrator < 2.60.18.0 RCE");
  script_summary(english:"Checks the version of HPE Smart Storage Administrator.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Smart Storage Administrator installed on the
remote Windows host is prior to 2.60.18.0. It is, therefore, affected
by a flaw in function isDirectFileAccess() in file ipcelmclient.php
due to improper sanitization of user-supplied input to the 'command'
variable. An authenticated, remote attacker can exploit this, via a
specially crafted HTTP request, to execute arbitrary code on the
system.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05382349
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb134051");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HPE Smart Storage Administrator version 2.60.18.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hpe:smart_storage_administrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("hpe_smart_storage_administrator_installed.nbin");
  script_require_keys("installed_sw/HPE Smart Storage Administrator");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "HPE Smart Storage Administrator";
fix = "2.60.18.0";
install = get_single_install(app_name:app_name,exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'];

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (empty_or_null(port))
    port = 445;

  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
