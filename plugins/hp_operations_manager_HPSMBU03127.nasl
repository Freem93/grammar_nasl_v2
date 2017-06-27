#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78512);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/20 15:01:13 $");

  script_cve_id("CVE-2014-2648", "CVE-2014-2649");
  script_bugtraq_id(70350, 70353);
  script_osvdb_id(113004, 113005);
  script_xref(name:"HP", value:"emr_na-c04472866");
  script_xref(name:"IAVB", value:"2014-B-0145");
  script_xref(name:"HP", value:"HPSBMU03127");
  script_xref(name:"HP", value:"SSRT101727");

  script_name(english:"HP Operations Manager 9.10 / 9.11 / 9.20 Multiple RCE");
  script_summary(english:"Checks the version and patches of HP Operations Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The version of HP Operations Manager for Unix installed on the remote
host is 9.10, 9.11, or 9.20 without the vendor-supplied patches. It
is, therefore, affected by multiple unspecified flaws that allow an
unauthenticated, remote attacker to execute arbitrary code.");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04472866
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20372ce3");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("hp_om_linux_installed.nbin");
  script_require_keys("installed_sw/HPOM_Linux");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

install = get_single_install(app_name:"HPOM_Linux", exit_if_unknown_ver:TRUE);
srv_ver = install["version"];
patches = install["Installed Patches"];
path = install["path"];

report = NULL;
# 9.10 / 9.11 have 2 patches
if (srv_ver =~ "^9\.1[0-1]\.")
{
  patch1 = eregmatch(string:patches, pattern:"OMLPATCH_00080_[0-9]+-[0-9.].*");
  patch2 = eregmatch(string:patches, pattern:"OMLPATCH_00081_[0-9]+-[0-9.].*");
  if (empty_or_null(patch1)) report += '\n  Missing Patch     : OML_00080';
  if (empty_or_null(patch2)) report += '\n  Missing Patch     : OML_00081';
}
# 9.20 only 1 patch
else if (srv_ver =~ "^9\.20\.")
{
  patched = eregmatch(string:patches, pattern:"OMLPATCH_00082_[0-9]+-[0-9.].*");
  if (empty_or_null(patched)) report = '\n  Missing Patch     : OML_00082';
}
else audit(AUDIT_INST_PATH_NOT_VULN, "HP Operations Manager", srv_ver, path);

if (!empty_or_null(report))
{
  report = '\n  Installed version : '+srv_ver + 
           report+
           '\n';
  security_hole(port:0, extra:report);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "HP Operations Manager");
