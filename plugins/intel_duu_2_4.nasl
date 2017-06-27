#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88577);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id("CVE-2016-1493");
  script_osvdb_id(133395);

  script_name(english:"Intel Driver Update Utility 2.x < 2.4 Cleartext Download MitM");
  script_summary(english:"Checks the version of Intel Driver Update Utility.");

  script_set_attribute(attribute:"synopsis", value:
"The Intel Driver Update Utility installed on the remote Windows host
is affected by a man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Intel Driver Update Utility installed on the remote
host is 2.x prior to 2.4. It is, therefore, affected by a
man-in-the-middle vulnerability due to the transmission of driver
updates in cleartext. A man-in-the-middle attacker can exploit this to
disclose or manipulate data, potentially resulting in the execution of
arbitrary code via a crafted malicious update.");
  # https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00048&languageid=en-fr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddad21f6");
  # http://www.coresecurity.com/advisories/intel-driver-update-utility-mitm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73ab0374");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel Driver Update Utility version 2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:driver_update_utility");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("intel_duu_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Intel Driver Update Utility");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Intel Driver Update Utility";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

if (version =~ "^2\." && ver_compare(ver:version, fix:"2.4.0.5", strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (empty_or_null(port))
    port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 2.4.0.5' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
