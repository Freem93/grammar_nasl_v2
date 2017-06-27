#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73102);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2014-0895");
  script_bugtraq_id(66116);
  script_osvdb_id(104368);

  script_name(english:"IBM SPSS SamplePower 3.0.1 < 3.0.1 IF2 vsflex8l ActiveX Control Remote Code Execution");
  script_summary(english:"Checks version of the vsflex8l.ocx ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control that is affected by a remote
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of IBM SPSS SamplePower 3.0.1
prior to Interim Fix 2.  It is, therefore, affected by a remote code
execution vulnerability related to a flaw in the vsflex8l ActiveX
control."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_ibm_spss_samplepower_vsflex8l_activex_control_combolist_property_remote_code_execution_vulnerability_cve_2014_0895?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a999c99d");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21666790");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM SPSS SamplePower 3.0.1 IF 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:spss_samplepower");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_spss_sample_power_installed.nasl");
  script_require_keys("SMB/ibm_spss_samplepower/Version", "SMB/ibm_spss_samplepower/Path");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

app_name = 'IBM SPSS SamplePower';

app_version = get_kb_item_or_exit("SMB/ibm_spss_samplepower/Version");
install_path = get_kb_item_or_exit("SMB/ibm_spss_samplepower/Path");

# If version isn't 3.0.1, then the install isn't vulnerable.
if (app_version !~ "^3\.0\.1$") audit(AUDIT_INST_PATH_NOT_VULN, app_name, app_version, install_path);

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL,"activex_init()");

# Determine if the control is installed
clsid = '{0F026C11-5A66-4C2B-87B5-88DDEBAE72A1}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_filename');
}

if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

activex_end();

fixed = '8.0.20141.300';

# Compare versions of activeX file.
if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
    '\n  Application         : ' + app_name +
    '\n  Application version : ' + app_version +
    '\n  Class identifier    : ' + clsid +
    '\n  File name           : ' + file +
    '\n  Installed version   : ' + version +
    '\n  Fixed version       : ' + fixed +
    '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN,file,version);
