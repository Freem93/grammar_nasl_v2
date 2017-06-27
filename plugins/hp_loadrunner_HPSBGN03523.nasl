#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91571);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id(
    "CVE-2016-4359",
    "CVE-2016-4360",
    "CVE-2016-4361"
  );
  script_bugtraq_id(90975);
  script_osvdb_id(
    139285,
    139286, 
    139287,
    144644
  );
  script_xref(name:"HP", value:"HPSBGN03609");
  script_xref(name:"HP", value:"PSRT110020");
  script_xref(name:"HP", value:"PSRT110032");
  script_xref(name:"HP", value:"SSRT102274");
  script_xref(name:"HP", value:"emr_na-c05157423");
  script_xref(name:"ZDI", value:"ZDI-16-363");
  script_xref(name:"ZDI", value:"ZDI-16-364");
  script_xref(name:"TRA", value:"TRA-2016-16");
  script_xref(name:"TRA", value:"TRA-2016-17");
  script_xref(name:"TRA", value:"TRA-2016-26");

  script_name(english:"HP LoadRunner 11.52 / 12.00 / 12.01 / 12.02 / 12.50 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of an HP LoadRunner library file.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote Windows host is
11.52, 12.00, 12.01, 12.02, or 12.50, without the HPSBGN03609 hotfix.
It is, therefore, affected by multiple vulnerabilities :

  - An overflow condition exists in mchan.dll due to a
    failure to validate the size of a user-supplied string
    prior to copying it to a stack-based buffer. An
    unauthenticated, remote attacker can exploit this to
    cause a stack-based buffer overflow, resulting in the
    execution of arbitrary code. (CVE-2016-4359)
  
  - A flaw exists in the CSV import feature when handling
    file paths. An unauthenticated, remote attacker can
    exploit this to delete arbitrary files on the remote
    system. (CVE-2016-4360)
  
  - A flaw exists in the magentservice.exe service that is
    triggered when handling malformed xdr_string fields in a
    series of service connection requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to crash the service,
    resulting in a denial of service condition.
    (CVE-2016-4361)");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05157423
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a216ffbd");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-16");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-17");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP LoadRunner version 12.53 or later. Alternatively, apply
the HPSBGN03609 hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('misc_func.inc');
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "HP LoadRunner";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path    = install['path'];
verui   = install['display_version'];
vuln	= FALSE;
mchan_path = path + "\bin";
patched_mchan = "";
display_fix = verui + " with HPSBGN03609 hotfix";

# only affected: 11.52, 12.00, 12.01, 12.20, 12.50
if (verui == "11.52")
  patched_mchan = "11.52.5098.0";
else if (verui == "12.00")
  patched_mchan = "12.0.1916.0";
else if (verui == "12.01")
  patched_mchan = "12.0.2887.0";
else if (verui == "12.02")
  patched_mchan = "12.00.3410.0";
else if (verui == "12.50")
  patched_mchan = "12.50.975.0";

if (!empty_or_null(patched_mchan))
{
  # check for patched mchan.dll
  hotfix_check_fversion_init();

  r = hotfix_check_fversion(file:"mchan.dll", version:patched_mchan, path:mchan_path);
  if (r == HCF_OLDER)
    vuln = TRUE;
  else
    hotfix_handle_error(error_code:r, file:mchan_path + "\mchan.dll", appname:app_name, exit_on_fail:TRUE);

  hotfix_check_fversion_end();
}

if (!vuln)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

port = kb_smb_transport();

order = make_list("Installed version", "Fixed version", "Path");
report = make_array(
  order[0], verui,
  order[1], display_fix,
  order[2], path
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
