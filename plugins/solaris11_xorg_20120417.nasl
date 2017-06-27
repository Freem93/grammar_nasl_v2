#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80818);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-4028", "CVE-2011-4029");

  script_name(english:"Oracle Solaris Third-Party Patch Update : xorg (cve_2011_4028_information_disclosure)");
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

  - The LockServer function in os/utils.c in X.Org xserver
    before 1.11.2 allows local users to determine the
    existence of arbitrary files via a symlink attack on a
    temporary lock file, which is handled differently if the
    file exists. (CVE-2011-4028)

  - The LockServer function in os/utils.c in X.Org xserver
    before 1.11.2 allows local users to change the
    permissions of arbitrary files to 444, read those files,
    and possibly cause a denial of service (removed
    execution permission) via a symlink attack on a
    temporary lock file. (CVE-2011-4029)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2011_4028_information_disclosure
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e70bba2"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2011_4029_race_condition
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1e3334e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 6.6.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:xorg");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/17");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^xorg$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.6.0.6.0", sru:"SRU 6.6") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : xorg\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_note(port:0, extra:error_extra);
  else security_note(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "xorg");
