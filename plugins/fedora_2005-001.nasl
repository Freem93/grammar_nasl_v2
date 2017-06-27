#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-001.
#

include("compat.inc");

if (description)
{
  script_id(16113);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_cve_id("CVE-2005-0021", "CVE-2005-0022");
  script_xref(name:"FEDORA", value:"2005-001");

  script_name(english:"Fedora Core 2 : exim-4.43-1.FC2.1 (2005-001)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This erratum fixes two relatively minor security issues which were
discovered in Exim in the last few weeks. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the names
CVE-2005-0021 and CVE-2005-0022 to these, respectively.

1. The function host_aton() can overflow a buffer if it is presented
with an illegal IPv6 address that has more than 8 components.

2. The second report described a buffer overflow in the function
spa_base64_to_bits(), which is part of the code for SPA
authentication. This code originated in the Samba project. The
overflow can be exploited only if you are using SPA authentication.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-January/000555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?080b4ac1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exim-sa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/07");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"exim-4.43-1.FC2.1")) flag++;
if (rpm_check(release:"FC2", reference:"exim-debuginfo-4.43-1.FC2.1")) flag++;
if (rpm_check(release:"FC2", reference:"exim-doc-4.43-1.FC2.1")) flag++;
if (rpm_check(release:"FC2", reference:"exim-mon-4.43-1.FC2.1")) flag++;
if (rpm_check(release:"FC2", reference:"exim-sa-4.43-1.FC2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-doc / exim-mon / exim-sa");
}
