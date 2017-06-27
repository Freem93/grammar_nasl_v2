#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80645);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-4339");

  script_name(english:"Oracle Solaris Third-Party Patch Update : ipmitool (cve_2011_4339_access_controls)");
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

  - ipmievd (aka the IPMI event daemon) in OpenIPMI, as used
    in the ipmitool package 1.8.11 in Red Hat Enterprise
    Linux (RHEL) 6, Debian GNU/Linux, Fedora 16, and other
    products uses 0666 permissions for its ipmievd.pid PID
    file, which allows local users to kill arbitrary
    processes by writing to this file. (CVE-2011-4339)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2011_4339_access_controls
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88039c9c"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 13.4.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:ipmitool");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^ipmitool$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipmitool");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.13.0.4.0", sru:"SRU 13.4") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : ipmitool\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_note(port:0, extra:error_extra);
  else security_note(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "ipmitool");
