#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83736);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/19 18:32:15 $");

  script_cve_id("CVE-2015-2219", "CVE-2015-2233", "CVE-2015-2234");
  script_bugtraq_id(74634, 74642, 74649);
  script_osvdb_id(121521, 121522, 121523);

  script_name(english:"Lenovo System Update < 5.06.0034 Multiple Vulnerabilities");
  script_summary(english:"Checks the file version of Lenovo System Update.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Lenovo System Update installed on the remote host is
prior to 5.06.0034. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists in SUService.exe (System Update service)
    due to generating security tokens for a named pipe in a
    predictable manner. A local attacker, by sending a valid
    token, can exploit this flaw to execute commands to gain
    elevated privileges. (CVE-2015-2219)

  - A flaw exists due to a failure to properly validate the
    certificate authority chain when downloading updates. A
    man-in-the-middle attacker, using a crafted certificate,
    can exploit this flaw to inject malicious updates,
    thereby allowing the execution of arbitrary files.
    (CVE-2015-2233)

  - A flaw exists due to signature validation for updates
    occurring in a directory having world-writeable
    permissions. This can allow a local attacker to swap the
    update before it is installed and thereby gain elevated
    privileges. (CVE-2015-2234)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.lenovo.com/us/en/product_security/lsu_privilege");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lenovo System Update 5.06.0034 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Lenovo System Update Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lenovo:system_update");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("lenovo_su_detection.nbin");
  script_require_keys("installed_sw/Lenovo System Update");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Lenovo System Update";

install = get_single_install(app_name: app, exit_if_unknown_ver: TRUE);

path = install['path'];
version = install['version'];

fix = "5.6.0.34";

# Versions < 5.6.0.34 are vulnerable.
if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    productname = get_kb_item("SMB/ProductName");

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version;

    if ( "XP" >< productname || "Vista" >< productname)
    {
      report +=
        '\n' +
        '\n  Lenovo System Update is no longer supported on Windows XP and Windows Vista hosts.' +
        '\n  Please refer to the vendor advisory for more information.' +
        '\n';
    }
    else
    {
      report +=
        '\n  Fixed version     : ' + fix +
        '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
