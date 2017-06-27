#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80766);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-6150", "CVE-2013-4408");

  script_name(english:"Oracle Solaris Third-Party Patch Update : samba (cve_2012_6150_input_validation)");
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

  - The winbind_name_list_to_sid_string_list function in
    nsswitch/pam_winbind.c in Samba through 4.1.2 handles
    invalid require_membership_of group names by accepting
    authentication by any user, which allows remote
    authenticated users to bypass intended access
    restrictions in opportunistic circumstances by
    leveraging an administrator's pam_winbind
    configuration-file mistake. (CVE-2012-6150)

  - Heap-based buffer overflow in the
    dcerpc_read_ncacn_packet_done function in
    librpc/rpc/dcerpc_util.c in winbindd in Samba 3.x before
    3.6.22, 4.0.x before 4.0.13, and 4.1.x before 4.1.3
    allows remote AD domain controllers to execute arbitrary
    code via an invalid fragment length in a DCE-RPC packet.
    (CVE-2013-4408)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2012_6150_input_validation
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec644489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2013_4408_buffer_errors"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.16.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:samba");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^samba$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.16.0.5.0", sru:"SRU 11.1.16.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : samba\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "samba");
