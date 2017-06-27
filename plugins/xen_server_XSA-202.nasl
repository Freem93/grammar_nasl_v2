#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96958);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2016-10024");
  script_bugtraq_id(95021);
  script_osvdb_id(149100);
  script_xref(name:"IAVB", value:"2017-B-0008");

  script_name(english:"Xen Asynchronous Modification EFLAGS.IF Clearing DoS (XSA-202)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is missing a security update. It is,
therefore, affected by a denial of service vulnerability due to a flaw
in the x86 instruction emulator whenever a guest asynchronously
modifies its instruction stream to effect the clearing of EFLAGS.IF.
An attacker who has guest kernel administrator privileges can exploit
this issue to cause the host to hang or crash.

Please note the following items :

  - Only x86 PV guests can exploit the vulnerability.

  - Neither ARM guests nor x86 HVM guests can exploit the
    vulnerability.

Note that Nessus has not tested for this vulnerability but has instead
relied only on the changeset versions based on the xen.git change log.
Nessus did not check guest hardware configurations or if patches were
applied manually to the source code before a recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-202.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
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

# XSA-202 4.4
fixes['4.4']['fixed_ver']           = '4.4.4';
fixes['4.4']['fixed_ver_display']   = '4.4.4 (changeset 394ddc2)';
fixes['4.4']['affected_ver_regex']  = '^4\\.4\\.';
fixes['4.4']['affected_changesets'] = make_list("5a343e4", "619db7d",
  "149c34a", "1c1bfc1", "6639a20", "14fa85a", "1827d52", "e8a46a2",
  "ed77368", "488b7d2", "dfddbf3", "2f3e08d", "fbe0fb4", "0fe7d69",
  "36a5a87", "27f0143", "ec5925c", "aea2669", "8ce712f", "45c1210",
  "a0b99ab", "9b2061d", "35fe0d6", "7e42cb6", "c1f9a26", "0eb5ef2",
  "98d7429", "2dbe363", "5f07492", "3534322", "6428217", "17d7046",
  "7bd50f1", "6f76ac2", "5519488", "04e831a", "9b7d6d2", "76a62af",
  "0006b20", "08a1d2b", "0b5c527", "6e86c87", "cbbb4d1", "e9c81e9",
  "01311b9", "09f9f79", "ab6f899", "6717d99", "5cf1b52", "24ebffa",
  "c2f8ab3", "0ae1e71", "83c5e46", "02426e9", "46b8f78", "ff87c9a",
  "a611ed5");

# XSA-202 4.5
fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 0bd7faf)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("e3426e2", "37281bc",
  "27be856", "bdf3ef1", "cc325c0", "8e7b84d", "387b8ae", "34fbae7",
  "1530da2", "274a1f6", "b679cfa", "877b760", "cfe165d", "84e4e56",
  "e4ae4b0");

# XSA-202 4.6
fixes['4.6']['fixed_ver']           = '4.6.5';
fixes['4.6']['fixed_ver_display']   = '4.6.5-pre (changeset c7f06e4)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("aa281a1", "ac699ed",
  "57e3ac3", "7789292", "62add85", "22f70a3", "0ba9562", "7902dba",
  "5f85ab0", "7bd27ba", "514173d", "a4902ca", "c03035b", "e0fbb85",
  "fcab9d3", "46529a1", "ffda122", "805bb93");

# XSA-202 4.7
fixes['4.7']['fixed_ver']           = '4.7.2';
fixes['4.7']['fixed_ver_display']   = '4.7.2-pre (changeset c2a7cc9)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("c5feb91", "7a71cea",
  "e0ea04d", "4be57d3", "e144f21", "0726cb5", "32282af", "cf21f0c",
  "a2d232d", "206fc70", "a6b0650", "98eaf9c", "1b65a34", "8ce2238",
  "2cd9fa0", "42bc34b", "e98e17e", "0561a33");

# XSA-202 4.8
fixes['4.8']['fixed_ver']           = '4.8.1';
fixes['4.8']['fixed_ver_display']   = '4.8.1-pre (changeset 7628c7e)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("b996efb", "7967daf",
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

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
