#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(99130);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/03 15:09:40 $");

  script_cve_id(
    "CVE-2017-4903",
    "CVE-2017-4904",
    "CVE-2017-4905"
  );
  script_bugtraq_id(
    97160,
    97164,
    97165
  );
  script_osvdb_id(
    154017,
    154021,
    154022
  );
  script_xref(name:"VMSA", value:"2017-0006");
  script_xref(name:"IAVB", value:"2017-B-0037");

  script_name(english:"ESXi 6.0 U1 < Build 5251621 / 6.0 U2 < Build 5251623 / 6.0 U3 < Build 5224934 Multiple Vulnerabilities (VMSA-2017-0006) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 6.0 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote VMware ESXi 6.0 host is 6.0 U1 prior to
build 5251621, 6.0 U2 prior to build 5251623, or 6.0 U3 prior to build
5224934. It is, therefore, affected by multiple vulnerabilities :

  - A stack memory initialization flaw exists that allows an
    attacker on the guest to execute arbitrary code on the
    host. (CVE-2017-4903)

  - An unspecified flaw exists in memory initialization that
    allows an attacker on the guest to execute arbitrary
    code on the host. (CVE-2017-4904)

  - An unspecified flaw exists in memory initialization that
    allows the disclosure of sensitive information.
    (CVE-2017-4905)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2017-0006.html");
  # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2149672
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29e8975b");
  # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2149673
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ac633b1");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi600-201703401-SG, ESXi600-201703002, or
ESXi600-201703003 according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 6.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 6.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "6.0");

build = int(match[1]);
vuln = FALSE;

# 6.0 U1 Builds
# KB 2149672
u1_builds = make_list(3029758, 3073146, 3247720, 3380124, 3568940);
foreach u1_build (u1_builds)
{
  if (build == u1_build)
  {
    vuln = TRUE;
    fixed_build = 5251621;
  }
}

# 6.0 U2 Builds
# KB 2149673
u1_builds = make_list(3620759, 3825889, 4192238, 4510822, 4600944);
foreach u1_build (u1_builds)
{
  if (build == u1_build)
  {
    vuln = TRUE;
    fixed_build = 5251623;
  }
}

# 6.0 U3
# KB 2143832 lists 5050593 as the build for 6.0 U3 released on 2/24/17
if (!vuln)
{
  if (build >= 5050593 && build < 5224934)
  {
    vuln = TRUE;
    fixed_build = 5224934;
  }
}

if (vuln)
{
  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
