#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91230);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/22 04:42:08 $");

  script_cve_id("CVE-2016-2334", "CVE-2016-2335");
  script_bugtraq_id(90531);
  script_osvdb_id(138424, 138425);
  script_xref(name:"IAVA", value:"2016-A-0139");

  script_name(english:"7-Zip < 16.00 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of 7-Zip.");

  script_set_attribute(attribute:"synopsis", value:
"A compression utility installed on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of 7-Zip installed on the remote Windows host is prior to
16.0. It is, therefore, affected by multiple vulnerabilities :

  - A heap buffer overflow condition exits in the
    CHandler::ExtractZlibFile() function within file
    Archive\HfsHandler.cpp due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this by convincing a user to open a
    specially crafted file, resulting in the execution of
    arbitrary code. (CVE-2016-2334)

  - An out-of-bounds read error exists in the
    CInArchive::ReadFileItem() function within file
    Archive\Udf\UdfIn.cpp when handling Universal Disk
    Format (UDF) files. An unauthenticated, remote attacker
    can exploit this by convincing a user to open a
    specially crafted UDF file, resulting in the execution
    of arbitrary code. (CVE-2016-2335)");
  script_set_attribute(attribute:"see_also", value:"http://www.talosintel.com/reports/TALOS-2016-0093/");
  script_set_attribute(attribute:"see_also", value:"http://www.talosintel.com/reports/TALOS-2016-0094/");
  script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/p/sevenzip/discussion/45797/thread/a8fd6078/");
  script_set_attribute(attribute:"see_also", value:"http://www.7-zip.org/history.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7-Zip version 16.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("7zip_installed.nbin");
  script_require_keys("installed_sw/7-Zip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = '7-Zip';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

fix = "16.00";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version);
