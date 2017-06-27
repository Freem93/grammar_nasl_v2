#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95630);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 18:13:38 $");

  script_cve_id(
    "CVE-2016-9377",
    "CVE-2016-9378",
    "CVE-2016-9379",
    "CVE-2016-9380",
    "CVE-2016-9381",
    "CVE-2016-9382",
    "CVE-2016-9383",
    "CVE-2016-9384",
    "CVE-2016-9385",
    "CVE-2016-9386"
  );
  script_bugtraq_id(
    94468,
    94470,
    94471,
    94472,
    94473,
    94474,
    94475,
    94476
  );
  script_osvdb_id(
    147621,
    147622,
    147623,
    147652,
    147653,
    147654,
    147655,
    147656,
    147657,
    147658
  );
  script_xref(name:"IAVB", value:"2016-B-0177");

  script_name(english:"Xen Multiple Vulnerabilities (XSA-191 - XSA-198)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in the inject_swint() function in
    x86_emulate.c due to improper handling of the format of
    IDT lookups when emulating instructions which generate
    software interrupts. A guest attacker can exploit this
    to crash the host, resulting in a denial of service
    condition. (CVE-2016-9377)

  - A flaw exists in the svm_inject_trap() function in svm.c
    due to a failure to properly perform IDT privilege
    checks when emulating instructions which generate
    software interrupts. A guest attacker can exploit this
    to crash the host, resulting in a denial of service
    condition. (CVE-2016-9378)

  - A flaw exists in the sniff_netware() function in file
    tools/pygrub/src/pygrub due to improper handling of
    string quotes and S-expressions in the bootloader when
    the S-expressions output format is requested. A guest
    attacker can exploit this to cause the bootloader
    configuration file to produce incorrect output,
    resulting in the disclosure or deletion of files from
    the host. (CVE-2016-9379)

  - A flaw exists in the sniff_netware() function in file
    tools/pygrub/src/pygrub due to improper handling of NULL
    bytes in the bootloader when the null-delimited output
    format is requested. A guest attacker can exploit this
    to cause configuration files to output ambiguous or
    confusing results, resulting in the disclosure or
    deletion of files from the host. (CVE-2016-9380)

  - A double-fetch flaw exists that is triggered when the
    compiler omits QEMU optimizations. A guest attacker can
    exploit this to gain elevated privileges on the host.
    (CVE-2016-9381)

  - A flaw exists in the hvm_task_switch() function in hvm.c
    due to improper handling of x86 task switching to VM86
    mode. A guest attacker can exploit this to cause a
    denial of service condition or gain elevated privileges
    within the guest environment. (CVE-2016-9382)

  - A flaw exists in the x86_emulate() function in
    x86_emulate.c that allows a guest attacker to cause
    changes to memory and thereby gain elevated privileges
    on the host. (CVE-2016-9383)

  - A flaw exists that is triggered as unused bytes in 
    image metadata are not properly cleared during symbol 
    table loading. This may allow a guest attacker to 
    disclose potentially sensitive information from the 
    host. (CVE-2016-9384)

  - A flaw exists due to improper clearing of unused bytes
    in image metadata during symbol table loading. A guest
    attacker can exploit this to disclose sensitive
    information from the host. (CVE-2016-9384)

  - A flaw exists in the x86 segment base write emulation
    due to a lack of canonical address checks. A guest
    attacker can exploit this issue to crash the host,
    resulting in a denial of service condition.
    (CVE-2016-9385)

  - A flaw exists in the x86 emulator due to improper
    validation of the usability of segments when performing
    memory accesses. A guest attacker can exploit this to
    gain elevated privileges within the guest environment.
    (CVE-2016-9386)

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-191.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-192.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-193.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-194.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-195.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-196.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-197.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-198.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/11/22");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "Xen Hypervisor";
install  = get_single_install(app_name:app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version         = install['version'];
display_version = install['display_version'];
path            = install['path'];
managed_status  = install['Managed status'];
changeset       = install['Changeset'];

if (!empty_or_null(changeset))
  display_version += " (changeset " + changeset + ")";

# Installations that are vendor-managed are handled by OS-specific local package checks
if (managed_status == "managed")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

fixes['4.7']['fixed_ver']           = '4.7.2';
fixes['4.7']['fixed_ver_display']   = '4.7.2-pre (changeset 206fc70)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("a6b0650", "98eaf9c",
  "1b65a34", "8ce2238", "2cd9fa0", "42bc34b", "e98e17e", "0561a33");

fixes['4.6']['fixed_ver']           = '4.6.5';
fixes['4.6']['fixed_ver_display']   = '4.6.5-pre (changeset 514173d)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("a4902ca", "c03035b",
  "e0fbb85", "fcab9d3", "46529a1", "ffda122", "805bb93");

fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 8e7b84d)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("387b8ae", "34fbae7",
  "1530da2", "274a1f6", "b679cfa", "877b760", "cfe165d", "84e4e56",
  "e4ae4b0");

fixes['4.4']['fixed_ver']           = '4.4.4';
fixes['4.4']['fixed_ver_display']   = '4.4.4 (changeset 6639a20)';
fixes['4.4']['affected_ver_regex']  = '^4\\.4\\.';
fixes['4.4']['affected_changesets'] = make_list("14fa85a", "1827d52",
  "e8a46a2", "ed77368", "488b7d2", "dfddbf3", "2f3e08d", "fbe0fb4",
  "0fe7d69", "36a5a87", "27f0143", "ec5925c", "aea2669", "8ce712f",
  "45c1210", "a0b99ab", "9b2061d", "35fe0d6", "7e42cb6", "c1f9a26",
  "0eb5ef2", "98d7429", "2dbe363", "5f07492", "3534322", "6428217",
  "17d7046", "7bd50f1", "6f76ac2", "5519488", "04e831a", "9b7d6d2",
  "76a62af", "0006b20", "08a1d2b", "0b5c527", "6e86c87", "cbbb4d1",
  "e9c81e9", "01311b9", "09f9f79", "ab6f899", "6717d99", "5cf1b52",
  "24ebffa", "c2f8ab3", "0ae1e71", "83c5e46", "02426e9", "46b8f78",
  "ff87c9a", "a611ed5");

fix = NULL;
foreach ver_branch (keys(fixes))
{
  if (version =~ fixes[ver_branch]['affected_ver_regex'])
  {
    ret = ver_compare(ver:version, fix:fixes[ver_branch]['fixed_ver']);
    if (ret < 0)
      fix = fixes[ver_branch]['fixed_ver_display'];
    else if (ret == 0)
    {
      if (empty_or_null(changeset))
        fix = fixes[ver_branch]['fixed_ver_display'];
      else
        foreach affected_changeset (fixes[ver_branch]['affected_changesets'])
          if (changeset == affected_changeset)
            fix = fixes[ver_branch]['fixed_ver_display'];
    }
  }
}

if (empty_or_null(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

items  = make_array("Installed version", display_version,
                    "Fixed version", fix,
                    "Path", path);
order  = make_list("Path", "Installed version", "Fixed version");
report = report_items_str(report_items:items, ordered_fields:order) + '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
