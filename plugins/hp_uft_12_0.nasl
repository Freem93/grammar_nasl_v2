#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73094);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/08 22:46:49 $");

  script_cve_id("CVE-2013-6210");
  script_bugtraq_id(66197);
  script_osvdb_id(104439);
  script_xref(name:"HP", value:"emr_na-c04122007");
  script_xref(name:"HP", value:"SSRT101287");
  script_xref(name:"HP", value:"HPSBMU02967");

  script_name(english:"HP Unified Functional Testing < 12.0 Remote Code Execution (HPSBMU02967)");
  script_summary(english:"Checks local version of HP UFT");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of HP Unified Functional Testing
prior to 12.0. It is, therefore, affected by an unspecified remote
code execution vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-063/");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c04122007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3592786");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 12.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:unified_functional_testing");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("hp_unified_functional_testing_installed.nbin");
  script_require_keys("SMB/hp_uft/path", "SMB/hp_uft/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "HP Unified Functional Testing";
path = get_kb_item_or_exit("SMB/hp_uft/path");
version = get_kb_item_or_exit("SMB/hp_uft/version");

fix = '12.0';

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
