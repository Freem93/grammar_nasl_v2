#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93802);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/03 18:13:38 $");

  script_cve_id(
    "CVE-2016-7093",
    "CVE-2016-7094"
  );
  script_bugtraq_id(
    92864,
    92865
  );
  script_osvdb_id(
    143907,
    143916
  );
  script_xref(name:"IAVB", value:"2016-B-0140");

  script_name(english:"Xen Multiple Vulnerabilities (XSA-186, XSA-187)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by multiple vulnerabilities :

- A flaw exists due to improper handling of instruction
  pointer truncation when emulating HVM instructions. An
  attacker on the guest can exploit this to gain elevated
  privileges on the host. (CVE-2016-7093)

- An overflow condition exists due to x86 HVM guests running
  with shadow paging using a subset of the x86 emulator to
  handle the guest writing to pagetables. An attacker on the
  guest can exploit this to cause a denial of service
  condition on the host. (CVE-2016-7094)

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-186.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-187.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/29");

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

fixes['4.7']['fixed_ver']           = '4.7.1';
fixes['4.7']['fixed_ver_display']   = '4.7.1-pre (changeset 0c9b942)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("cb3397a", "6825f37",
  "dbeb5da", "9d2ede8", "ba1f4a4", "4f610f2", "7743e91", "93429d2",
  "b80d7eb", "fb87d02", "ed48c80", "dbaf2c8", "80bc435", "fd7306f",
  "5b5abe1", "8224649", "de781b4", "ab75cdf", "78a3010", "f2160ba",
  "471a151", "c732d3c", "d37c2b9", "899495b", "b1ba8c0", "a492556",
  "22ec349", "df39cfa", "11e3c4a");

fixes['4.6']['fixed_ver']           = '4.6.4';
fixes['4.6']['fixed_ver_display']   = '4.6.4-pre (changeset 26352b6)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("be8c32a", "f984f6e",
  "4627e5e", "1663655", "5bb458b", "40592ed", "0d9c05d", "a149a6e",
  "4260eef", "a00a0f9", "4f78b27", "e06d2ba", "0e94436", "77a9be9",
  "29e5892", "f8972b4", "2c11229", "55292d3");

fixes['4.5']['fixed_ver']           = '4.5.4';
fixes['4.5']['fixed_ver_display']   = '4.5.4-pre (changeset 433ebca)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("bc9f72b", "ec88876",
  "d50078b", "42ea059", "9e06b02", "e824aae", "2e56416", "cda8e7e",
  "462f714", "de1d9ea", "2ad058e", "50a4501", "8ca7cf8", "9eb11dc",
  "e86a6fb", "08313b4", "0fc8aab", "c18c145", "505ad3a", "c421378",
  "b1f4e86", "cfcdeea", "c4c0312", "467f77d", "eadd663", "818d58d",
  "071d2e3", "44a703d", "6d27298", "6338746", "df9c5c4", "d8ac67e",
  "509ae90", "3675172", "8df6d98", "1a75ae1", "6925b22", "517d1d8",
  "31be4b9", "bbbe635", "382ed2f", "c9b8314", "3a3c8b2", "2614f9a",
  "a81a94d", "c7e9c4b", "2388be0", "2cd66e8", "eaf75a3", "840a49a",
  "27874bc", "6265a6f", "e08efef", "1c44339", "a848f24", "ec5591d",
  "cc0376e", "f9d0a2c", "f058444", "24f5f12", "16cb1fb", "2aef428",
  "2978e1a", "8c4b403", "524a93d", "8549385", "b1c94bd", "644aa81",
  "e5fa482", "8d1e559", "f332597", "c790220", "49fe83a", "a67e0f1",
  "ffda547", "d4d3739", "facf156", "62e8902", "4065709", "d19f941",
  "c0bb033", "1334fa9", "478ad3f", "2c438f8", "2bc9bd9", "350eb39",
  "065b134", "f9cc40e", "becb125", "0aabc28", "12acca5", "9945f62",
  "38eee32", "c70ab64", "1f92bdb", "7eb2fae");

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
