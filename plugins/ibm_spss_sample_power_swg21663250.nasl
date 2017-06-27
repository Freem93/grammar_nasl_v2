#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72368);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/08 00:28:11 $");

  script_cve_id("CVE-2013-6724");
  script_bugtraq_id(65273);
  script_osvdb_id(102718);

  script_name(english:"IBM SPSS SamplePower 3.0.1 < 3.0.1 IF1 ActiveX Control Remote Code Execution");
  script_summary(english:"Checks time-stamp of SamplePower executable.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control with a remote code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of IBM SPSS SamplePower 3.0.1
prior to Interim Fix 1.  It is, therefore, affected by a remote code
execution vulnerability related to a flaw in the 'Vsflex8l.ocx' ActiveX
control."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-039/");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_ibm_spss_samplepower_vsflex8l_activex_control_combolist_property_remote_code_execution_vulnerability_cve_2013_6724?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb96d89");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21663250");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM SPSS SamplePower 3.0.1 IF 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:spss_samplepower");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_spss_sample_power_installed.nasl");
  script_require_keys("SMB/ibm_spss_samplepower/Version", "SMB/ibm_spss_samplepower/Path");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("datetime.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/ibm_spss_samplepower/Version");
install_path = get_kb_item_or_exit("SMB/ibm_spss_samplepower/Path");

app_name = "IBM SPSS SamplePower";

# If version isn't 3.0.1, then the install isn't vulnerable.
if (version !~ "^3\.0\.1$") audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

# Interim Fix consists of a patched EXE, so look at the timestamp.
file_path = hotfix_append_path(path:install_path, value:"SamplePower.exe");
file_timestamp = hotfix_get_timestamp(path:file_path);

hotfix_handle_error(error_code:file_timestamp['error'],
                    file:file_path,
                    appname:app_name,
                    exit_on_fail:TRUE);

hotfix_check_fversion_end();

timestamp = file_timestamp['value'];
fix_timestamp = 1388681321;

# Compare timestamp to fixed timestamp and report.
if (timestamp < fix_timestamp)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
    '\n  Path              : ' + install_path +
    '\n  Installed version : ' + version +
    '\n  File              : ' + file_path +
    '\n  File timestamp    : ' + strftime(timestamp) +
    '\n  Fixed timestamp   : ' + strftime(fix_timestamp) +
    '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);
