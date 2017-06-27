#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-1120.
#

include("compat.inc");

if (description)
{
  script_id(72050);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:06:08 $");

  script_cve_id("CVE-2013-1740");
  script_xref(name:"FEDORA", value:"2014-1120");

  script_name(english:"Fedora 20 : nss-3.15.4-1.fc20 / nss-softokn-3.15.4-1.fc20 / nss-util-3.15.4-1.fc20 (2014-1120)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update of the nss, nss-softokn, and nss-util packages to nss-3.15.4, a
patch release for NSS 3.15 which includes the following
security-relevant bug :

(CVE-2013-1740) When false start is enabled, libssl will sometimes
return unencrypted, unauthenticated data from PR_Recv

For further details refer to the nss upstream release notes at

https://developer.mozilla.org/en-US/docs/NSS/NSS_3.15.4_release_notes

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.mozilla.org/en-US/docs/NSS/NSS_3.15.4_release_notes"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?451ef35a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c7c4bd7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5edbe705"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss, nss-softokn and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"nss-3.15.4-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"nss-softokn-3.15.4-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"nss-util-3.15.4-1.fc20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-softokn / nss-util");
}
