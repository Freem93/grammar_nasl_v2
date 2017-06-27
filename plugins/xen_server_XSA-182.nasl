#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92701);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/03 18:13:38 $");

  script_cve_id("CVE-2016-6258");
  script_bugtraq_id(92131);
  script_osvdb_id(142140);
  script_xref(name:"IAVB", value:"2016-B-0118");

  script_name(english:"Xen Privilege Escalation (XSA-182) (Bunker Buster)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Xen
hypervisor is affected by a privilege escalation vulnerability in the
paravirtualization (PV) pagetable implementation due to incorrect
usage of fast-paths for making updates to pre-existing pagetable
entries. An attacker with administrative privileges on a PV guest can
exploit this vulnerability to gain administrative privileges on the
host operating system. This vulnerability only affects PV guests on
x86 hardware; HVM and ARM guests are not affected.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-182.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  # http://www.scmagazine.com/xen-hypervisor-vulnerability-found/article/512550/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5242c966");
  # https://nakedsecurity.sophos.com/2016/07/28/the-xen-bunker-buster-bug-what-you-need-to-know/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83872af7");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value: "2016/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

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
fixes['4.7']['fixed_ver_display']   = '4.7.1-pre (changeset b1ba8c0)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("a492556", "22ec349", "df39cfa", "11e3c4a");

fixes['4.6']['fixed_ver']           = '4.6.3';
fixes['4.6']['fixed_ver_display']   = '4.6.3 (changeset eac595f)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("285248d");

fixes['4.5']['fixed_ver']           = '4.5.4';
fixes['4.5']['fixed_ver_display']   = '4.5.4-pre (changeset 467f77d)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("eadd663", "818d58d", "071d2e3", "44a703d",
    "6d27298", "6338746", "df9c5c4", "d8ac67e", "509ae90", "3675172", "8df6d98", "1a75ae1",
    "6925b22", "517d1d8", "31be4b9", "bbbe635", "382ed2f", "c9b8314", "3a3c8b2", "2614f9a",
    "a81a94d", "c7e9c4b", "2388be0", "2cd66e8", "eaf75a3", "840a49a", "27874bc", "6265a6f",
    "e08efef", "1c44339", "a848f24", "ec5591d", "cc0376e", "f9d0a2c", "f058444", "24f5f12",
    "16cb1fb", "2aef428", "2978e1a", "8c4b403", "524a93d", "8549385", "b1c94bd", "644aa81",
    "e5fa482", "8d1e559", "f332597", "c790220", "49fe83a", "a67e0f1", "ffda547", "d4d3739",
    "facf156", "62e8902", "4065709", "d19f941", "c0bb033", "1334fa9", "478ad3f", "2c438f8",
    "2bc9bd9", "350eb39", "065b134", "f9cc40e", "becb125", "0aabc28", "12acca5", "9945f62",
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
