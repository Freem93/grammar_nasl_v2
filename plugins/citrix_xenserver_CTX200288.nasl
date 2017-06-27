#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79745);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/08 14:50:45 $");

  script_cve_id(
    "CVE-2014-1666",
    "CVE-2014-8595",
    "CVE-2014-8866",
    "CVE-2014-8867"
  );
  script_bugtraq_id(65125, 71151, 71331, 71332);
  script_osvdb_id(102536, 114852, 115137, 115138);

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX200288)");
  script_summary(english:"Checks XenServer version and installed hotfixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Citrix XenServer that is
affected by multiple vulnerabilities :

  - A local privilege escalation vulnerability exists
    due to improperly restricted access to
    'PHYSDEVOP_{prepare,release}_msix' operations by
    unprivileged guests. An attacker with access to a guest
    operating system can exploit this issue to gain elevated
    privileges on affected computers. (CVE-2014-1666)

  - A local privilege escalation vulnerability exists
    due to missing privilege level checks in x86 emulation
    of far branches. This flaw exists in the CALL, JMP, and
    RETF instructions in the Intel assembly syntax, and the
    LCALL, LJMP, and LRET instructions in the AT&T syntax.
    An attacker with access to a guest operating system can
    exploit this issue to gain elevated privileges on
    affected computers. (CVE-2014-8595)

  - A denial of service vulnerability exists due to a
    failure to restrict access to the hypercall argument
    translation feature. An attacker with access to a guest
    operating system can crash the host with excessive
    checks on the final register state for 32-bit guests
    running on a 64-bit hypervisor. (CVE-2014-8866)

  - A denial of service vulnerability exists due to
    insufficient bounding of 'REP MOVS' to MMIO emulated
    inside of the hypervisor. This flaw affects the
    'hvm_mmio_intercept()' function in 'intercept.c'. An
    attacker with access to a guest operating system can
    exploit this issue to crash the host.
    (CVE-2014-8867)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX200288");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

# We will do our checks within the branches because 6.0.2 needs
# special treatment.
if (version == "6.0.0")
{
  fix = "XS60E042";
  if ("XS60E042" >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E038 or XS602ECC014";
  if ("XS602E038" >!< patches && "XS602ECC014" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E045";
  if ("XS61E045" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1015";
  if ("XS62ESP1015" >!< patches) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report =
    '\n  Installed version : ' + version +
    '\n  Missing hotfix    : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, extra:report, port:port);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
