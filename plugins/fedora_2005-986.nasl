#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-986.
#

include("compat.inc");

if (description)
{
  script_id(20023);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:38:06 $");

  script_xref(name:"FEDORA", value:"2005-986");

  script_name(english:"Fedora Core 4 : openssl-0.9.7f-7.10 / openssl097a-0.9.7a-3.1 (2005-986)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora Core host is missing one or more security updates :

openssl-0.9.7f-7.10 :

  - Wed Oct 12 2005 Tomas Mraz <tmraz at redhat.com>
    0.9.7f-7.10

    - fix CVE-2005-2969 - remove
      SSL_OP_MSIE_SSLV2_RSA_PADDING which disables the
      countermeasure against man in the middle attack in
      SSLv2 (#169863)

  - more fixes for constant time/memory access for DSA
    signature algorithm

    - updated ICA engine patch

    - ca-bundle.crt should be config(noreplace)

    - add *.so.soversion as symlinks in /lib (#165264)

    - remove unpackaged symlinks (#159595)

    - fixes from upstream (bn assembler div on ppc arch,
      initialize memory on realloc)

openssl097a-0.9.7a-3.1 :

  - Tue Oct 11 2005 Tomas Mraz <tmraz at redhat.com>
    0.9.7a-3.1

    - fix CVE-2005-2969 - remove
      SSL_OP_MSIE_SSLV2_RSA_PADDING which disables the
      countermeasure against man in the middle attack in
      SSLv2 (#169863)

  - more fixes for constant time/memory access for DSA
    signature algorithm

    - updated ICA engine patch

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-October/001488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53c3d395"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-October/001490.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f1f911c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssl097a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssl097a-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"openssl-0.9.7f-7.10")) flag++;
if (rpm_check(release:"FC4", reference:"openssl-debuginfo-0.9.7f-7.10")) flag++;
if (rpm_check(release:"FC4", reference:"openssl-devel-0.9.7f-7.10")) flag++;
if (rpm_check(release:"FC4", reference:"openssl-perl-0.9.7f-7.10")) flag++;
if (rpm_check(release:"FC4", reference:"openssl097a-0.9.7a-3.1")) flag++;
if (rpm_check(release:"FC4", reference:"openssl097a-debuginfo-0.9.7a-3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
