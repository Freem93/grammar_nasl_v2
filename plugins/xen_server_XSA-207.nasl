#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97388);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/28 14:42:20 $");

  script_osvdb_id(152191);

  script_name(english:"Xen Guest Destruction Memory Leak DoS (XSA-207)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is missing a security update. It is,
therefore, affected by a memory leak issue due to improper cleanup
during guest destruction. A guest attacker can exploit this issue, via
frequent rebooting, to eventually exhaust the system memory of the
host system, resulting in a denial service condition. Note that Intel
systems and systems without IOMMU/SMMU hardware are not affected by
this vulnerability.

Nessus has not tested for this vulnerability but has instead relied
only on the changeset versions based on the xen.git change log.
Additionally, Nessus did not check guest hardware configurations or if
patches were applied manually to the source code before a recompile
and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-207.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/02/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

# XSA-207 4.4
fixes['4.4']['fixed_ver']           = '4.4.4';
fixes['4.4']['fixed_ver_display']   = '4.4.4 (changeset b648113)';
fixes['4.4']['affected_ver_regex']  = '^4\\.4\\.';
fixes['4.4']['affected_changesets'] = make_list("394ddc2", "5a343e4",
  "619db7d", "149c34a", "1c1bfc1", "6639a20", "14fa85a", "1827d52",
  "e8a46a2", "ed77368", "488b7d2", "dfddbf3", "2f3e08d", "fbe0fb4",
  "0fe7d69", "36a5a87", "27f0143", "ec5925c", "aea2669", "8ce712f",
  "45c1210", "a0b99ab", "9b2061d", "35fe0d6", "7e42cb6", "c1f9a26",
  "0eb5ef2", "98d7429", "2dbe363", "5f07492", "3534322", "6428217",
  "17d7046", "7bd50f1", "6f76ac2", "5519488", "04e831a", "9b7d6d2",
  "76a62af", "0006b20", "08a1d2b", "0b5c527", "6e86c87", "cbbb4d1",
  "e9c81e9", "01311b9", "09f9f79", "ab6f899", "6717d99", "5cf1b52",
  "24ebffa", "c2f8ab3", "0ae1e71", "83c5e46", "02426e9", "46b8f78",
  "ff87c9a", "a611ed5");

# XSA-207 4.5
fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 43d06ef)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("2b17bf4", "1a2bda5",
  "0bd7faf", "e3426e2", "37281bc", "27be856", "bdf3ef1", "cc325c0",
  "8e7b84d", "387b8ae", "34fbae7", "1530da2", "274a1f6", "b679cfa",
  "877b760", "cfe165d", "84e4e56", "e4ae4b0");

# XSA-207 4.6
fixes['4.6']['fixed_ver']           = '4.6.5';
fixes['4.6']['fixed_ver_display']   = '4.6.5-pre (changeset 8e04cb2)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("576f319", "163543a",
  "5c38a2e", "d3630ca", "ae02630", "09f521a", "3658f7a", "ccb36fb",
  "2109ae6", "2f8bdf1", "1d6ced7", "de45d24", "40837a3", "468a313",
  "b8da9cd", "70ee582", "5331244", "ce6048f", "57a09d7", "23fc18b",
  "e1c3fc3", "9784802", "f7c3199", "49e6fcd", "422575d", "fbef3be",
  "e87481f", "cebf5ac", "6af399d", "69baa97", "a240dc0", "9b401e4",
  "2eb074f", "c7f06e4", "aa281a1", "ac699ed", "57e3ac3", "7789292",
  "62add85", "22f70a3", "0ba9562", "7902dba", "5f85ab0", "7bd27ba",
  "514173d", "a4902ca", "c03035b", "e0fbb85", "fcab9d3", "46529a1",
  "ffda122", "805bb93");

# XSA-207 4.7
fixes['4.7']['fixed_ver']           = '4.7.2';
fixes['4.7']['fixed_ver_display']   = '4.7.2-pre (changeset 7583782)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("d31a0a2", "5bc9c62",
  "1f2fe76", "386acdb", "5cadc66", "67d0d5e", "ae3fa02", "88ca94a",
  "dc309dd", "013ee59", "5f65c8d", "d2fd4ab", "71d99ec", "5cb968a",
  "8f4b369", "5da121c", "24dc627", "6d0af98", "93daaf9", "7829149",
  "f4dc0d2", "ff555d5", "fd869a6", "dca0501", "7524025", "6d55b3a",
  "149eb6b", "ba5bfeb", "a94f6d5", "d651253", "792dda0", "dd65186",
  "0ad7781", "6ddc1f3", "9f3c555", "c2a7cc9", "c5feb91", "7a71cea",
  "e0ea04d", "4be57d3", "e144f21", "0726cb5", "32282af", "cf21f0c",
  "a2d232d", "206fc70", "a6b0650", "98eaf9c", "1b65a34", "8ce2238",
  "2cd9fa0", "42bc34b", "e98e17e", "0561a33");

# XSA-207 4.8
fixes['4.8']['fixed_ver']           = '4.8.1';
fixes['4.8']['fixed_ver_display']   = '4.8.1-pre (changeset c246296)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("10baa19", "4582c2b",
  "a20300b", "23e3303", "95f1f99", "9b0e6d3", "b843de7", "ba7e250",
  "6240d92", "b378b1f", "b29aed8", "e1cefed", "53c3a73", "daf491d",
  "a654228", "c581ead", "67e9679", "080a31b", "1febe8d", "7713ee2",
  "b76a796", "e298344", "6933092", "af6534e", "297cf3d", "3e902dd",
  "c5efe95", "63c68c7", "3667bc0", "86e54be", "e7ad85e", "bdbfca0",
  "443264e", "d575902", "24ccfc3", "7628c7e", "b996efb", "7967daf",
  "1f4ea16");

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

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
