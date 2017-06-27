#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95539);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/06 20:05:59 $");

  script_cve_id(
    "CVE-2016-9379",
    "CVE-2016-9380",
    "CVE-2016-9381",
    "CVE-2016-9382",
    "CVE-2016-9383",
    "CVE-2016-9385",
    "CVE-2016-9386"
  );
  script_bugtraq_id(
    94470,
    94471,
    94472,
    94473,
    94474,
    94476
  );
  script_osvdb_id(
    147621,
    147622,
    147623,
    147653,
    147655,
    147656,
    147657
  );

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX218775)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in the sniff_netware() function within
    file tools/pygrub/src/pygrub when handling string quotes
    and S-expressions in the bootloader whenever the
    S-expressions output format is requested. A guest
    attacker can exploit this to cause the bootloader
    configuration file to produce incorrect output,
    resulting in the disclosure or deletion of files from
    the host. (CVE-2016-9379)

  - A flaw exists in the sniff_netware() function within
    file tools/pygrub/src/pygrub when handling NULL bytes in
    the bootloader whenever the null-delimited output format
    is requested. A guest attacker can exploit this to cause
    configuration files to output ambiguous or confusing
    results, resulting in the disclosure or deletion of files
    from the host. (CVE-2016-9380)

  - A double-fetch flaw exists that is triggered when the
    compiler omits QEMU optimizations. A guest attacker can
    exploit this to gain elevated privileges on the host.
    (CVE-2016-9381)

  - A flaw exists in the hvm_task_switch() function within
    file arch/x86/hvm/hvm.c due to improper handling of x86
    task switching to VM86 mode. A guest attacker can
    exploit this to cause a denial of service condition or
    gain elevated privileges within the guest environment.
    (CVE-2016-9382)

  - A flaw exists in the x86_emulate() function within
    file arch/x86/x86_emulate/x86_emulate.c that allows a
    guest attacker to cause changes to memory and thereby
    gain elevated privileges on the host. (CVE-2016-9383)

  - A denial of service vulnerability exists in the x86
    segment base write emulation that is related to lacking
    canonical address checks. A local attacker who has
    administrative rights within a guest can exploit this
    issue to crash the host. (CVE-2016-9385)

  - A flaw exists in the x86 emulator due to improper
    checking of the usability of segments when performing
    memory accesses. A guest attacker can exploit this to
    gain elevated privileges. (CVE-2016-9386)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX218775");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/11/22");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
  fix = "XS602ECC037";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1052";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1042 and XS65ESP1043";
  if (("XS65ESP1042" >!< patches) || ("XS65ESP1043" >!< patches)) vuln = TRUE;
}
else if (version =~ "^7\.0")
{
  fix = "XS70E019, XS70E020, and XS70E021";
  if (("XS70E019" >!< patches) || ("XS70E020" >!< patches) || ("XS70E021" >!< patches)) vuln = TRUE;
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
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
