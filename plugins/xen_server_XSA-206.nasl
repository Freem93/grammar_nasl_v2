#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99398);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/14 20:11:15 $");

  script_bugtraq_id(97250);
  script_osvdb_id(154806);

  script_name(english:"Xen Hypervisor xenstored Write Saturation DoS (XSA-206)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by a denial of service
vulnerability in xenstored during processing of transactions. An
attacker on the guest can exploit this vulnerability by issuing
repeated writes to xenstore that conflict with transactions either of
the toolstack or backends, such as the driver domain, causing the
transactions made by these entities to fail indefinitely.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-206.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

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

# XSA-206

fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset ac3d8bc)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("cde86fc", "1678521",
  "83cb2db", "43d06ef", "2b17bf4", "1a2bda5", "0bd7faf", "e3426e2",
  "37281bc", "27be856", "bdf3ef1", "cc325c0", "8e7b84d", "387b8ae",
  "34fbae7", "1530da2", "274a1f6", "b679cfa", "877b760", "cfe165d",
  "84e4e56", "e4ae4b0");

fixes['4.6']['fixed_ver']           = '4.6.6';
fixes['4.6']['fixed_ver_display']   = '4.6.6-pre (changeset f6d0888)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("bb92bb7", "ef63a62",
  "f96efeb", "7ff6d9f", "7017321", "541ad61", "4f96171", "9eb0aa2",
  "ac4c5d4", "18949dc", "eea0742", "90ae9a7", "ef5eb08", "48c3bd0");

fixes['4.7']['fixed_ver']           = '4.7.3';
fixes['4.7']['fixed_ver_display']   = '4.7.3-pre (changeset 8b77a2c)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("b5c7dea", "e0b9499",
  "ada9e10", "4bd66bc", "47ba140", "4a1dc28", "5466c77", "25f3d95",
  "e5e7f35", "683b886", "9f2540d", "9d9be1e", "ac8d90e", "bc868a2",
  "d5f9489", "b2a180e", "01abcc0", "9c404df", "ddc0cfe", "9a54dcd",
  "4351611", "c782e61", "d166f07", "099f67b", "d756bf1", "10debc0",
  "461dba2", "188809f", "3daa62a");

fixes['4.8']['fixed_ver']           = '4.8.1';
fixes['4.8']['fixed_ver_display']   = '4.8.1-pre (changeset 4cd02a2)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("e0354e6", "a085f0c",
  "ec7f9e1", "06403aa", "f3623bd", "c95bad9", "4ec1cb0", "093a1f1",
  "47501b6", "2859b25", "ca41491", "26dec7a", "eca97a4", "c75fe64",
  "af18ca9", "30c2dd7", "1780ea7", "42290f0", "bd684c2", "783b670",
  "07f9ddf", "d31d0cd", "b2e678e", "05946b5", "e020ff3", "308c646",
  "fceae91", "f667393", "768b250", "049b13d", "e26a2a0", "866f363",
  "354c3e4", "8c2da8f", "6289c3b", "2e68fda", "f85fc97", "9967251",
  "34305da", "437a8e6", "9028ba8", "1c28394", "c246296", "10baa19",
  "4582c2b", "a20300b", "23e3303", "95f1f99", "9b0e6d3", "b843de7",
  "ba7e250", "6240d92", "b378b1f", "b29aed8", "e1cefed", "53c3a73",
  "daf491d", "a654228", "c581ead", "67e9679", "080a31b", "1febe8d",
  "7713ee2", "b76a796", "e298344", "6933092", "af6534e", "297cf3d",
  "3e902dd", "c5efe95", "63c68c7", "3667bc0", "86e54be", "e7ad85e",
  "bdbfca0", "443264e", "d575902", "24ccfc3", "7628c7e", "b996efb",
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

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
