#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96778);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/06 20:05:59 $");

  script_cve_id(
    "CVE-2016-9932",
    "CVE-2016-10024",
    "CVE-2016-10025"
  );
  script_bugtraq_id(
    94863,
    95021,
    95026
  );
  script_osvdb_id(
    148798,
    149100,
    149105
  );
  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX219378)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in x86 instruction CMPXCHG8B due to legacy
    operand size overrides not being properly ignored when
    handling prefixes. A guest attacker can exploit this to
    disclose potentially sensitive information on the host
    system. Note that the ability to read a small amount of
    hypervisor memory is restricted to privileged-mode code
    in all guests except on Citrix XenServer 6.2 SP1 and
    6.0.2CC, where the attack may also be performed from
    non-privileged-mode code in HVM guest VMs.
    (CVE-2016-9932)

  - A denial of service vulnerability exists when a guest
    asynchronously modifies its instruction stream to effect
    the clearing of EFLAGS.IF. A guest attacker can exploit
    this to cause the host to hang or crash.
    (CVE-2016-10024)

  - A denial of service vulnerability exists due to a NULL
    pointer dereference flaw that is triggered when the
    hvmemul_vmfunc() function pointer uses inappropriate
    NULL checks before indirect function calls. A guest
    attacker can exploit this to cause the hypervisor to
    crash. Note that the ability of privileged-mode code in
    HVM guest VMs to crash the host is restricted to AMD
    systems running Citrix XenServer 7.0. (CVE-2016-10025)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX219378");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

if (version == "6.0.2")
{
  fix = "XS602ECC039"; # CTX219501
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1054"; # CTX219500
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1046"; # CTX219499
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0")
{
  fix = "XS70E023"; # CTX219498
  if (fix >!< patches) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Missing hotfix", fix
    ),
    ordered_fields:make_list("Installed version", "Missing hotfix")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
