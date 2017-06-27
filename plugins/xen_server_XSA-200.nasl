#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96957);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/23 14:56:48 $");

  script_cve_id("CVE-2016-9932");
  script_bugtraq_id(94863);
  script_osvdb_id(148798);

  script_name(english:"Xen CMPXCHG8B Emulation Information Disclosure (XSA-200)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is missing a security update. It is,
therefore, affected by an information disclosure vulnerability due to
a flaw in the x86 instruction CMPXCHG8B when handling prefixes. This
is triggered because legacy operand size overrides are not properly
ignored. A guest attacker can exploit this issue to disclose
potentially sensitive information from the hypervisor stack of the
host system.

Please note the following items :

  - Only x86 systems are affected. ARM systems are not
    affected.

  - On Xen version 4.6 and earlier, the vulnerability is
    exposed to all HVM guest user processes, including
    unprivileged processes.

  - On Xen version 4.7, the vulnerability is exposed only to
    HVM guest user processes granted a degree of privilege
    (e.g., direct hardware access) by the guest
    administrator, or else to all user processes when the VM
    has been explicitly configured with a non-default CPU
    vendor string (in xm/xl, this would be done with a
    'cpuid=' domain config option).

Note that Nessus has not tested for this vulnerability but has instead
relied only on the changeset versions based on the xen.git change log.
Nessus did not check guest hardware configurations or if patches were
applied manually to the source code before a recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-200.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");

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

fixes['4.4']['fixed_ver']           = '4.4.4';
fixes['4.4']['fixed_ver_display']   = '4.4.4 (changeset 619db7d)';
fixes['4.4']['affected_ver_regex']  = '^4\\.4\\.';
fixes['4.4']['affected_changesets'] = make_list("149c34a", "1c1bfc1",
  "6639a20", "14fa85a", "1827d52", "e8a46a2", "ed77368", "488b7d2",
  "dfddbf3", "2f3e08d", "fbe0fb4", "0fe7d69", "36a5a87", "27f0143",
  "ec5925c", "aea2669", "8ce712f", "45c1210", "a0b99ab", "9b2061d",
  "35fe0d6", "7e42cb6", "c1f9a26", "0eb5ef2", "98d7429", "2dbe363",
  "5f07492", "3534322", "6428217", "17d7046", "7bd50f1", "6f76ac2",
  "5519488", "04e831a", "9b7d6d2", "76a62af", "0006b20", "08a1d2b",
  "0b5c527", "6e86c87", "cbbb4d1", "e9c81e9", "01311b9", "09f9f79",
  "ab6f899", "6717d99", "5cf1b52", "24ebffa", "c2f8ab3", "0ae1e71",
  "83c5e46", "02426e9", "46b8f78", "ff87c9a", "a611ed5");

fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 37281bc)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("27be856", "bdf3ef1",
  "cc325c0", "8e7b84d", "387b8ae", "34fbae7", "1530da2", "274a1f6",
  "b679cfa", "877b760", "cfe165d", "84e4e56", "e4ae4b0");

fixes['4.6']['fixed_ver']           = '4.6.5';
fixes['4.6']['fixed_ver_display']   = '4.6.5-pre (changeset ac699ed)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("57e3ac3", "7789292",
  "62add85", "22f70a3", "0ba9562", "7902dba", "5f85ab0", "7bd27ba",
  "514173d", "a4902ca", "c03035b", "e0fbb85", "fcab9d3", "46529a1",
  "ffda122", "805bb93");

fixes['4.7']['fixed_ver']           = '4.7.2';
fixes['4.7']['fixed_ver_display']   = '4.7.2-pre (changeset e0ea04d)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("4be57d3", "e144f21",
  "0726cb5", "32282af", "cf21f0c", "a2d232d", "206fc70", "a6b0650",
  "98eaf9c", "1b65a34", "8ce2238", "2cd9fa0", "42bc34b", "e98e17e",
  "0561a33");

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
