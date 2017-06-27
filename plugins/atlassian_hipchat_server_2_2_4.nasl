#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100160);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/12 21:46:35 $");

  script_cve_id("CVE-2017-8080");
  script_bugtraq_id(98262);
  script_osvdb_id(156578);
  script_xref(name:"IAVA", value:"2017-A-0139");

  script_name(english:"Atlassian HipChat Server 1.0 < 2.2.4 Image Upload RCE");
  script_summary(english:"Checks hipchat-release for version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote chat server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian HipChat Server installed on the remote host
is 1.0 or later but prior to 2.2.4. It is, therefore, affected by a
remote code execution vulnerability due to improper validation of
uploaded images. An authenticated, remote attacker can exploit this,
via a specially crafted image, to execute arbitrary code.");
  # https://confluence.atlassian.com/hc/hipchat-server-security-advisory-2017-04-24-894234898.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fd02a11");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/HCPUB-2980");
  script_set_attribute(attribute:"solution", value:
"Update to Atlassian HipChat Server version 2.2.4 or later.
Alternatively, apply the patch specified in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:hipchat_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/HipChat", "Host/HipChat/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "HipChat Server";
fix = '2.2.4';
flag = 0;

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/HipChat/version");
if ( isnull(version) ) audit(AUDIT_OS_NOT, app);

# Affected Versions:
# 1.0 <= x
# x < 2.2.4
if (ver_compare(ver:version, fix:'1.0', strict:FALSE) < 0) audit(AUDIT_INST_VER_NOT_VULN, app, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  flag = 1;
  # Patch states it applies only to 2.2.2 and 2.2.3
  if (version =~ "^2\.2\.[23]$")
  {
    flag = 0;

    pkg_list = get_kb_item("Host/Debian/dpkg-l");
    if ( ! pkg_list ) audit(AUDIT_PACKAGE_LIST_MISSING);

    if ("ghostscript" >< pkg_list) flag = 1;
  }
}

if (flag)
{
    report =
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : ' + fix +
      '\n';

  security_report_v4(port: 0, severity: SECURITY_HOLE, extra: report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
