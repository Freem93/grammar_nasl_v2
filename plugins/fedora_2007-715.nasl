#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-715.
#

include("compat.inc");

if (description)
{
  script_id(27058);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/10/21 22:04:03 $");

  script_cve_id("CVE-2007-3102", "CVE-2007-4752");
  script_xref(name:"FEDORA", value:"2007-715");

  script_name(english:"Fedora Core 6 : openssh-4.3p2-25.fc6 (2007-715)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Oct 2 2007 Tomas Mraz <tmraz at redhat.com> -
    4.3p2-25

    - do not fall back on trusted X11 cookies
      (CVE-2007-4752) (#280471)

    - Fri Jul 13 2007 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-24

    - fixed audit log injection problem (CVE-2007-3102)
      (#248059)

    - Thu Jun 21 2007 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-23

    - document where the nss certificate and token dbs are
      looked for

    - Wed Jun 20 2007 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-22

    - experimental support for PKCS#11 tokens through
      libnss3 (#183423)

    - Tue Apr 3 2007 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-21

    - correctly setup context when empty level requested
      (#234951)

    - and always request default level as returned by
      getseuserbyname (#231695)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/004184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa57bba2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"openssh-4.3p2-25.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openssh-askpass-4.3p2-25.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openssh-clients-4.3p2-25.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openssh-debuginfo-4.3p2-25.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openssh-server-4.3p2-25.fc6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-debuginfo / etc");
}
