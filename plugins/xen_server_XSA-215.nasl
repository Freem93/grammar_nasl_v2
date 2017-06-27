#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100124);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/11 21:10:07 $");

  script_osvdb_id(
    156958,
    157110,
    157111,
    157112
  );
  script_xref(name:"IAVB", value:"2017-B-0050");

  script_name(english:"Xen Hypervisor Multiple Vulnerabilities (XSA-213 - XSA-215)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    get_user() function due to permissions for accessing
    MMIO ranges being checked only after accessing them. An
    attacker on the guest can exploit this to disclose
    potentially sensitive information in the host memory.
    (VulnDB 156958)

  - A privilege escalation vulnerability exists when an IRET
    hypercall is placed within a multicall batch due to
    improper handling of kernel-mode access to pagetables.
    An attacker on the guest can exploit this to access
    arbitrary system memory and gain elevated privileges on
    the host. (VulnDB 157110)

  - A privilege escalation vulnerability exists in the
    steal_page() function within file xen/arch/x86/mm.c when
    transferring pages from one guest to another PV guest
    with a different bitness or an HVM guest. An attacker
    with access to multiple guests can exploit this to
    access arbitrary system memory and gain elevated
    privileges on the host. (VulnDB 157111)

  - A flaw exists within arch/x86/x86_64/entry.S when
    handling failsafe callbacks due to improper validation
    of certain input. An attacker on the guest can exploit
    this to corrupt memory, potentially resulting in gaining
    elevated privileges. (VulnDB 157112)

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-213.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-214.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-215.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

# XSA-213
fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 6eb61e4)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("b1fcfed", "5779d6a",
  "afdd77e", "c18367a", "7b7fd80", "b30e165", "62ef9b2", "8071724",
  "235b5d5", "a28b99d", "ff294fc", "bc01e2d", "da50922", "386cc94",
  "139960f", "ec3ddd6", "988929a", "1c48dff", "20d4248", "9610422",
  "cd76cd3", "455fd66", "b820c31", "ac3d8bc", "cde86fc", "1678521",
  "83cb2db", "43d06ef", "2b17bf4", "1a2bda5", "0bd7faf", "e3426e2",
  "37281bc", "27be856", "bdf3ef1", "cc325c0", "8e7b84d", "387b8ae",
  "34fbae7", "1530da2", "274a1f6", "b679cfa", "877b760", "cfe165d",
  "84e4e56", "e4ae4b0");

fixes['4.6']['fixed_ver']           = '4.6.6';
fixes['4.6']['fixed_ver_display']   = '4.6.6-pre (changeset fc78396)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("cf35a35", "9746247",
  "f0f3d43", "d9c4094", "66cb2eb", "3d1affc", "4eff891", "05ccb71",
  "1eebd16", "f4d16c9", "9050a97", "5c609c8", "4d69c19", "ab889fb",
  "3073573", "bf22c39", "898b7c4", "159a610", "3972629", "ebb5a34",
  "a991af7", "06222e5", "a57a99a", "400063d", "f6d0888", "bb92bb7",
  "ef63a62", "f96efeb", "7ff6d9f", "7017321", "541ad61", "4f96171",
  "9eb0aa2", "ac4c5d4", "18949dc", "eea0742", "90ae9a7", "ef5eb08",
  "48c3bd0");

fixes['4.7']['fixed_ver']           = '4.7.3';
fixes['4.7']['fixed_ver_display']   = '4.7.3-pre (changeset c99967f)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("469fc7e", "6cf0da5",
  "c93ec9a", "e2141f1", "75ce43b", "a7f74db", "8106372", "5029638",
  "4a48e47", "167d989", "42ca46b", "d431ba3", "51833a2", "9e82ebf",
  "fb79c3a", "1df3d6c", "8b77a2c", "b5c7dea", "e0b9499", "ada9e10",
  "4bd66bc", "47ba140", "4a1dc28", "5466c77", "25f3d95", "e5e7f35",
  "683b886", "9f2540d", "9d9be1e", "ac8d90e", "bc868a2", "d5f9489",
  "b2a180e", "01abcc0", "9c404df", "ddc0cfe", "9a54dcd", "4351611",
  "c782e61", "d166f07", "099f67b", "d756bf1", "10debc0", "461dba2",
  "188809f", "3daa62a");

fixes['4.8']['fixed_ver']           = '4.8.1';
fixes['4.8']['fixed_ver_display']   = '4.8.1 (changeset 17051bd)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("98e05a3", "5ebb4de",
  "c2a5415");

# XSA-214
fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset d7e3725)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("6eb61e4", "b1fcfed",
  "5779d6a", "afdd77e", "c18367a", "7b7fd80", "b30e165", "62ef9b2",
  "8071724", "235b5d5", "a28b99d", "ff294fc", "bc01e2d", "da50922",
  "386cc94", "139960f", "ec3ddd6", "988929a", "1c48dff", "20d4248",
  "9610422", "cd76cd3", "455fd66", "b820c31", "ac3d8bc", "cde86fc",
  "1678521", "83cb2db", "43d06ef", "2b17bf4", "1a2bda5", "0bd7faf",
  "e3426e2", "37281bc", "27be856", "bdf3ef1", "cc325c0", "8e7b84d",
  "387b8ae", "34fbae7", "1530da2", "274a1f6", "b679cfa", "877b760",
  "cfe165d", "84e4e56", "e4ae4b0");

fixes['4.6']['fixed_ver']           = '4.6.6';
fixes['4.6']['fixed_ver_display']   = '4.6.6-pre (changeset dcef165)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("fc78396", "cf35a35",
  "9746247", "f0f3d43", "d9c4094", "66cb2eb", "3d1affc", "4eff891",
  "05ccb71", "1eebd16", "f4d16c9", "9050a97", "5c609c8", "4d69c19",
  "ab889fb", "3073573", "bf22c39", "898b7c4", "159a610", "3972629",
  "ebb5a34", "a991af7", "06222e5", "a57a99a", "400063d", "f6d0888",
  "bb92bb7", "ef63a62", "f96efeb", "7ff6d9f", "7017321", "541ad61",
  "4f96171", "9eb0aa2", "ac4c5d4", "18949dc", "eea0742", "90ae9a7",
  "ef5eb08", "48c3bd0");

fixes['4.7']['fixed_ver']           = '4.7.3';
fixes['4.7']['fixed_ver_display']   = '4.7.3-pre (changeset a7f041a)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("c99967f", "469fc7e",
  "6cf0da5", "c93ec9a", "e2141f1", "75ce43b", "a7f74db", "8106372",
  "5029638", "4a48e47", "167d989", "42ca46b", "d431ba3", "51833a2",
  "9e82ebf", "fb79c3a", "1df3d6c", "8b77a2c", "b5c7dea", "e0b9499",
  "ada9e10", "4bd66bc", "47ba140", "4a1dc28", "5466c77", "25f3d95",
  "e5e7f35", "683b886", "9f2540d", "9d9be1e", "ac8d90e", "bc868a2",
  "d5f9489", "b2a180e", "01abcc0", "9c404df", "ddc0cfe", "9a54dcd",
  "4351611", "c782e61", "d166f07", "099f67b", "d756bf1", "10debc0",
  "461dba2", "188809f", "3daa62a");

fixes['4.8']['fixed_ver']           = '4.8.1';
fixes['4.8']['fixed_ver_display']   = '4.8.1 (changeset 16ed8dd)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("17051bd", "98e05a3",
  "5ebb4de", "c2a5415");

# XSA-215
fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 8825df1)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("d7e3725", "6eb61e4",
  "b1fcfed", "5779d6a", "afdd77e", "c18367a", "7b7fd80", "b30e165",
  "62ef9b2", "8071724", "235b5d5", "a28b99d", "ff294fc", "bc01e2d",
  "da50922", "386cc94", "139960f", "ec3ddd6", "988929a", "1c48dff",
  "20d4248", "9610422", "cd76cd3", "455fd66", "b820c31", "ac3d8bc",
  "cde86fc", "1678521", "83cb2db", "43d06ef", "2b17bf4", "1a2bda5",
  "0bd7faf", "e3426e2", "37281bc", "27be856", "bdf3ef1", "cc325c0",
  "8e7b84d", "387b8ae", "34fbae7", "1530da2", "274a1f6", "b679cfa",
  "877b760", "cfe165d", "84e4e56", "e4ae4b0");

fixes['4.6']['fixed_ver']           = '4.6.6';
fixes['4.6']['fixed_ver_display']   = '4.6.6-pre (changeset eb9a3bf)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("dcef165", "fc78396",
  "cf35a35", "9746247", "f0f3d43", "d9c4094", "66cb2eb", "3d1affc",
  "4eff891", "05ccb71", "1eebd16", "f4d16c9", "9050a97", "5c609c8",
  "4d69c19", "ab889fb", "3073573", "bf22c39", "898b7c4", "159a610",
  "3972629", "ebb5a34", "a991af7", "06222e5", "a57a99a", "400063d",
  "f6d0888", "bb92bb7", "ef63a62", "f96efeb", "7ff6d9f", "7017321",
  "541ad61", "4f96171", "9eb0aa2", "ac4c5d4", "18949dc", "eea0742",
  "90ae9a7", "ef5eb08", "48c3bd0");

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
