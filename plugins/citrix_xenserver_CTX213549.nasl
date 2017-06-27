#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91885);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/06 20:05:59 $");

  script_cve_id("CVE-2016-5302");
  script_osvdb_id(139581);

  script_name(english:"Citrix XenServer Active Directory Authentication Incorrect Host Management Security Bypass (CTX213549, CTX213769)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is 7.x
prior to 7.0 hotfix XS70E003. It is, therefore, affected by a security
bypass vulnerability due to incorrect handling of Active Directory
(AD) credentials. An unauthenticated, remote attacker on the
management network with AD credentials for an AD account can exploit
this to compromise the XenServer host even if the credentials do not
have authorization.");
  script_set_attribute(attribute:"see_also",value:"https://support.citrix.com/article/CTX213549");
  script_set_attribute(attribute:"see_also",value:"https://support.citrix.com/article/CTX213769");
  script_set_attribute(attribute:"solution", value:
"Apply hotfix XS70E003 as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/28");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Settings/ParanoidReport", "Host/XenServer/version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");

# There are several mitigations for this issue:
#   - If AD auth has even briefly been disabled, the host is not vulnerable.
#   - This is only true for versions that have been upgraded from < 7 to 7.x,
#     not for new 7.0 installs
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

vuln = FALSE;
fix = 'XS70E003';

if (version !~ "^7\.0\.")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
else if (fix >< patches)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version + " with hotfix " +fix);
else
{
  port = 0;
  items = make_array("Installed version", version,
                     "Missing hotfix", fix
                    );

  order = make_list("Installed version", "Missing hotfix");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
