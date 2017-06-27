#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94162);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/03 18:13:38 $");

  script_cve_id("CVE-2016-7777");
  script_bugtraq_id(93344);
  script_osvdb_id(145066);
  script_xref(name:"IAVB", value:"2016-B-0149");

  script_name(english:"Xen x86 CR0.TS and CR0.EM Honoring Cross-task Register State Information Disclosure (XSA-190)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by an information disclosure
vulnerability in x86_emulate.c due to a failure to properly honor
CR0.TS and CR0.EM. A local attacker within an x86 HVM guest operating
system can exploit this, by modifying an instruction while the
hypervisor is preparing to emulate it, to read or manipulate FPU, MMX,
or XMM register state information for other tasks running in the
guest.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-190.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
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
fixes['4.7']['fixed_ver_display']   = '4.7.1-pre (changeset 3903db1)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("506182e", "33c4ba9",
  "ccae454", "dc57c17", "2d939ee", "24a1b18", "1983d58", "d515e86",
  "a7edbdc", "317eb71", "7e17174", "0e22f29", "b549cbd", "038aadd",
  "5c816c7", "129099b", "f515565", "c01565b", "0c9b942", "cb3397a",
  "6825f37", "dbeb5da", "9d2ede8", "ba1f4a4", "4f610f2", "7743e91",
  "93429d2", "b80d7eb", "fb87d02", "ed48c80", "dbaf2c8", "80bc435",
  "fd7306f", "5b5abe1", "8224649", "de781b4", "ab75cdf", "78a3010",
  "f2160ba", "471a151", "c732d3c", "d37c2b9", "899495b", "b1ba8c0",
  "a492556", "22ec349", "df39cfa", "11e3c4a");

fixes['4.6']['fixed_ver']           = '4.6.4';
fixes['4.6']['fixed_ver_display']   = '4.6.4-pre (changeset 4b41252)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("ef005cc", "e6f8bfb",
  "a4badfa", "d75fe0d", "223835f", "4511619", "8861999", "245fa11",
  "57dbc55", "cc977b7", "3cffa34", "6b5bb50", "c3b06b0", "7c86320",
  "9d819be", "26352b6", "be8c32a", "f984f6e", "4627e5e", "1663655",
  "5bb458b", "40592ed", "0d9c05d", "a149a6e", "4260eef", "a00a0f9",
  "4f78b27", "e06d2ba", "0e94436", "77a9be9", "29e5892", "f8972b4",
  "2c11229", "55292d3");

fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset cfe165d)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("84e4e56", "e4ae4b0");

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
