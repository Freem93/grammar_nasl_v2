#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71806);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/08/22 20:52:04 $");

  script_cve_id(
    "CVE-2013-2344",
    "CVE-2013-2345",
    "CVE-2013-2346",
    "CVE-2013-2347",
    "CVE-2013-2348",
    "CVE-2013-2349",
    "CVE-2013-2350",
    "CVE-2013-6194",
    "CVE-2013-6195"
  );
  script_bugtraq_id(64647);
  script_osvdb_id(
    101625,
    101626,
    101627,
    101628,
    101629,
    101630,
    101631,
    101634,
    101635
  );
  script_xref(name:"EDB-ID", value:"31689");

  script_name(english:"HP Data Protector Multiple Vulnerabilities (HPSBMU02895 SSRT101253)");
  script_summary(english:"Checks versions");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote HP Data Protector install is affected by multiple
vulnerabilities that could allow a remote attacker to gain elevated
privileges, trigger a denial of service vulnerability, or in the worst
case, execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-001");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-002");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-003");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-004");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-005");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-006");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-007");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-008");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-009");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03822422
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe03aaf8");
  script_set_attribute(attribute:"solution", value:"Patch the installation according to the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Data Protector Backup Client Service Directory Traversal');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/hp_openview_dataprotector", 5555);
  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_installed.nasl","hp_data_protector_installed_local.nasl");
  script_require_keys("Services/data_protector/version");

  exit(0);
}

include("hp_data_protector_version.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

# patterns matching affected platforms
hpux_pat = "^11\.(11|23|31)$";
solaris_pat = "^5(\.|$|[^0-9])";

# patterns for matching against affected versions
ver_621_pat = "^A\.06\.2[01]$";
ver_700_pat = "^A\.07\.0[01]$";
ver_800_pat = "^A\.08\.00$";
ver_810_pat = "^A\.08\.10$";

windows_pat = "^(5\.2|6\.0)$";
linux_pat = "(el[4-6]|SLES(9|10|11))(\.|$|[^0-9])";

# 6.21
hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_621_pat,
                        fixed_internal_build: 409,
                        comp_patches: make_array("core", 43781, "cell_server", 43780),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_621_pat,
                        fixed_internal_build: 409,
                        comp_patches: make_array("core", 273, "cell_server", 272),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"solaris",
                        os_version_pat: solaris_pat,
                        version_pat: ver_621_pat,
                        fixed_internal_build: 409,
                        comp_patches: make_array("core", 513, "cell_server", 512),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_621_pat,
                        fixed_internal_build: 409,
                        comp_patches: make_array("disk_agent", 666, "core", 665, "cell_server", 664),
                        severity: SECURITY_HOLE,
                        port:port);

# 7.00
windows_pat = "^(5\.2|6\.[012])$";
linux_pat = "(el[5-6]|SLES(10|11))(\.|$|[^0-9])";

hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: 106,
                        comp_patches: make_array("core", 43890, "cell_server", 43889),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: 106,
                        comp_patches: make_array("core", 288, "cell_server", 287),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: 106,
                        comp_patches: make_array("disk_agent", 684, "core", 669, "cell_server", 668),
                        severity: SECURITY_HOLE,
                        port:port);

# 8.00
hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_800_pat,
                        patch_bundle: 801,
                        fixed_internal_build: 600,
                        comp_patches: make_array("core"        , 43735, "cell_server", 43734,
                                                 "media_agent" , 43736, "disk_agent" , 43737,
                                                 "cell_console", 43738, "vepa"       , 43739),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_800_pat,
                        patch_bundle: 801,
                        fixed_internal_build: 600,
                        comp_patches: make_array("core"        , 265, "cell_server", 264,
                                                 "media_agent" , 266, "disk_agent" , 267,
                                                 "cell_console", 268, "vepa"       , 269),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_800_pat,
                        patch_bundle: 801,
                        fixed_internal_build: 600,
                        comp_patches: make_array("core"        , 659, "cell_server", 658,
                                                 "media_agent" , 660, "disk_agent" , 661,
                                                 "cell_console", 662, "vepa"       , 663),
                        severity: SECURITY_HOLE,
                        port:port);

# 8.10
hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_810_pat,
                        patch_bundle: 811,
                        fixed_internal_build: 200,
                        comp_patches: make_array("core"         , 43826, "cell_server", 43825,
                                                 "media_agent"  , 43828, "disk_agent" , 43827,
                                                 "cell_console" , 43829, "vepa"       , 43831,
                                                 "vmware_gre"   , 43840, "sos"        , 43832,
                                                 "emc"          , 43833, "sap_hana"   , 43834,
                                                 "documentation", 43830, "ssea"       , 43837,
                                                 "autodr"       , 43839),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_810_pat,
                        patch_bundle: 811,
                        fixed_internal_build: 200,
                        comp_patches: make_array("core"         , 275, "cell_server", 274,
                                                 "media_agent"  , 277, "disk_agent" , 276,
                                                 "cell_console" , 278, "vepa"       , 280,
                                                 "vmware_gre"   , 286, "sos"        , 281,
                                                 "emc"          , 285, "sap_hana"   , 282,
                                                 "documentation", 279, "ssea"       , 284,
                                                 "autodr"       , 283),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_810_pat,
                        patch_bundle: 811,
                        fixed_internal_build: 200,
                        comp_patches: make_array("core"        , 671, "cell_server"  , 670,
                                                 "media_agent" , 673, "disk_agent"   , 672,
                                                 "cell_console", 674, "vepa"         , 676,
                                                 "vmware_gre"  , 682, "sos"          , 677,
                                                 "emc"         , 680, "documentation", 675,
                                                 "autodr"      , 681),
                        severity: SECURITY_HOLE,
                        port:port);

# Not vuln if we've reached this point.  Exit with correct audit.
hp_data_protector_check_exit(port:port);

