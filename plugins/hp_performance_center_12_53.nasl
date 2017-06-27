#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93811);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id(
    "CVE-2016-4359",
    "CVE-2016-4360",
    "CVE-2016-4361",
    "CVE-2016-4384"
  );
  script_bugtraq_id(
    93069,
    90975
  );
  script_osvdb_id(
    139285,
    139286, 
    139287,
    144643,
    144644
  );
  script_xref(name:"HP", value:"emr_na-c05157423");
  script_xref(name:"HP", value:"emr_na-c05278882");
  script_xref(name:"HP", value:"HPSBGN03609");
  script_xref(name:"HP", value:"HPSBGN03648");
  script_xref(name:"HP", value:"PSRT110020");
  script_xref(name:"HP", value:"PSRT110032");
  script_xref(name:"HP", value:"PSRT110230");
  script_xref(name:"HP", value:"SSRT102274");
  script_xref(name:"TRA", value:"TRA-2016-16");
  script_xref(name:"TRA", value:"TRA-2016-17");
  script_xref(name:"TRA", value:"TRA-2016-26");
  script_xref(name:"ZDI", value:"ZDI-16-363");
  script_xref(name:"ZDI", value:"ZDI-16-364");

  script_name(english:"HP Performance Center 11.52.x / 12.x < 12.53 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Performance Center.");

  script_set_attribute(attribute:"synopsis", value:
"A software performance testing application installed on the remote
Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Performance Center installed on the remote Windows
host is 11.52.x or 12.x prior to 12.53. It is, therefore, affected by
multiple vulnerabilities :

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
    (CVE-2016-4361)

  - A flaw exists in the mchan.dll library due to improper
    parsing of malformed packets. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to crash the service, resulting in a denial of
    service condition. (CVE-2016-4384)");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05157423
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a216ffbd");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05278882
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?491a66db");  
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-16");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-17");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Performance Center version 12.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:performance_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("hp_performance_center_installed.nbin");
  script_require_keys("installed_sw/HP Performance Center");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = "HP Performance Center";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
fix = "12.53";

# For CVE-2016-4384, all prior to 12.50 listed as vuln.
# However, 12.53 is listed as fix.
# Other CVEs: 11.52/12.00/12.01/12.02/12.50 up to patch 1 listed as vuln

if(ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
