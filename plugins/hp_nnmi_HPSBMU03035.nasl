#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79800);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2013-6220");
  script_osvdb_id(106799);
  script_bugtraq_id(67314,67305);
  script_xref(name:"HP", value:"HPSBMU03035");
  script_xref(name:"HP", value:"SSRT101479");
  script_xref(name:"HP", value:"emr_na-c04273695");

  script_name(english:"HP Network Node Manager i (NNMi) XSS (HPSBMU03035)");
  script_summary(english:"Checks the version of HP Network Node Manager i.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Network Node Manager i (NNMi) installed on the
remote host is a version that is potentially affected by an XSS
vulnerability.

Note that Nessus did not check for the presence of a patch.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04273695
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42c03506");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.0 or apply the hotfix referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_nnmi_installed_windows.nasl");
  script_require_keys("Settings/ParanoidReport","installed_sw/HP Network Node Manager i","SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Force windows only
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "HP Network Node Manager i";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ver      = install["version"];
path     = install["path"   ];
port     = get_kb_item("SMB/transport");
if(isnull(port)) port = 445;

if (ver !~ "^9\.(00?|10|20)(\.|$)") audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

# We don't check if the hotfix has been applied.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver  +
    '\n  Fixed version     : 10.0' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
