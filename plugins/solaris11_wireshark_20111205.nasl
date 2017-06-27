#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80800);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-3266", "CVE-2011-3360", "CVE-2011-4101");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (denial_of_service_vulnerability_in)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - The proto_tree_add_item function in Wireshark 1.6.0
    through 1.6.1 and 1.4.0 through 1.4.8, when the IKEv1
    protocol dissector is used, allows user-assisted remote
    attackers to cause a denial of service (infinite loop)
    via vectors involving a malformed IKE packet and many
    items in a tree. (CVE-2011-3266)

  - Untrusted search path vulnerability in Wireshark 1.4.x
    before 1.4.9 and 1.6.x before 1.6.2 allows local users
    to gain privileges via a Trojan horse Lua script in an
    unspecified directory. (CVE-2011-3360)

  - The dissect_infiniband_common function in
    epan/dissectors/packet-infiniband.c in the Infiniband
    dissector in Wireshark 1.4.0 through 1.4.9 and 1.6.x
    before 1.6.3 allows remote attackers to cause a denial
    of service (NULL pointer dereference and application
    crash) via a malformed packet. (CVE-2011-4101)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/denial_of_service_vulnerability_in
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82815ebc"
  );
  # https://blogs.oracle.com/sunsecurity/entry/denial_of_service_vulnerability_in1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8ebbec1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/untrusted_search_path_vulnerability_in
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee2378b9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 02.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark console.lua Pre-Loading Script Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^wireshark$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.2.0.3.0", sru:"SRU 2") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
