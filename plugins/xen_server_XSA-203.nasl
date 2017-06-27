#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96959);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2016-10025");
  script_bugtraq_id(95026);
  script_osvdb_id(149105);
  script_xref(name:"IAVB", value:"2017-B-0008");

  script_name(english:"Xen Intel VMX hvmemul_vmfunc() NULL Pointer Dereference DoS (XSA-203)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is missing a security update. It is,
therefore, affected by a NULL pointer dereference flaw due to a
failure to utilize necessary NULL checks before doing indirect
function calls through the hvmemul_vmfunc() function pointer. A guest
attacker can exploit this issue to cause the hypervisor to crash,
resulting in a denial of service condition.

Please note the following items :

  - Only HVM guests can exploit the vulnerability. PV guests
    cannot exploit the vulnerability.

  - Only x86 systems are vulnerable that use SVM (AMD
    virtualization extensions) rather than VMX (Intel
    virtualization extensions). This applies to HVM guests
    on AMD x86 CPUs. Therefore, AMD x86 hardware is
    vulnerable whereas Intel hardware is not.

  - ARM systems are not affected by the vulnerability.

Note that Nessus has not tested for this vulnerability but has instead
relied only on the changeset versions based on the xen.git change log.
Nessus did not check guest hardware configurations or if patches were
applied manually to the source code before a recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-203.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/12/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");

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

# XSA-203 4.6
fixes['4.6']['fixed_ver']           = '4.6.5';
fixes['4.6']['fixed_ver_display']   = '4.6.5-pre (changeset 2eb074f)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("c7f06e4", "aa281a1",
  "ac699ed", "57e3ac3", "7789292", "62add85", "22f70a3", "0ba9562",
  "7902dba", "5f85ab0", "7bd27ba", "514173d", "a4902ca", "c03035b",
  "e0fbb85", "fcab9d3", "46529a1", "ffda122", "805bb93");

# XSA-203 4.7
fixes['4.7']['fixed_ver']           = '4.7.2';
fixes['4.7']['fixed_ver_display']   = '4.7.2-pre (changeset 9f3c555)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("c2a7cc9", "c5feb91",
  "7a71cea", "e0ea04d", "4be57d3", "e144f21", "0726cb5", "32282af",
  "cf21f0c", "a2d232d", "206fc70", "a6b0650", "98eaf9c", "1b65a34",
  "8ce2238", "2cd9fa0", "42bc34b", "e98e17e", "0561a33");

# XSA-203 4.8
fixes['4.8']['fixed_ver']           = '4.8.1';
fixes['4.8']['fixed_ver_display']   = '4.8.1-pre (changeset 24ccfc3)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("7628c7e", "b996efb",
  "7967daf", "1f4ea16");

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

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
