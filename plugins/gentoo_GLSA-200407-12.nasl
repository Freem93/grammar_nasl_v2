#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14545);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0626");
  script_osvdb_id(7316);
  script_xref(name:"GLSA", value:"200407-12");

  script_name(english:"GLSA-200407-12 : Linux Kernel: Remote DoS vulnerability with IPTables TCP Handling");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200407-12
(Linux Kernel: Remote DoS vulnerability with IPTables TCP Handling)

    An attacker can utilize an erroneous data type in the IPTables TCP option
    handling code, which lies in an iterator. By making a TCP packet with a
    header length larger than 127 bytes, a negative integer would be implied in
    the iterator.
  
Impact :

    By sending one malformed packet, the kernel could get stuck in a loop,
    consuming all of the CPU resources and rendering the machine useless,
    causing a Denial of Service. This vulnerability requires no local access.
  
Workaround :

    If users do not use the netfilter functionality or do not use any
    ``--tcp-option'' rules they are not vulnerable to this exploit. Users that
    are may remove netfilter support from their kernel or may remove any
    ``--tcp-option'' rules they might be using. However, all users are urged to
    upgrade their kernels to patched versions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users are encouraged to upgrade to the latest available sources for their
    system:
    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ck-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:development-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hardened-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mips-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mm-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pegasos-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsbac-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:uclinux-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermode-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:win4lin-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xbox-sources");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"sys-kernel/hppa-dev-sources", unaffected:make_list("ge 2.6.7_p1-r1"), vulnerable:make_list("lt 2.6.7_p1-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/development-sources", unaffected:make_list("ge 2.6.8"), vulnerable:make_list("lt 2.6.8"))) flag++;
if (qpkg_check(package:"sys-kernel/xbox-sources", unaffected:make_list("ge 2.6.7-r1", "lt 2.6"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-dev-sources", unaffected:make_list("ge 2.6.7-r1"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-dev-sources", unaffected:make_list("ge 2.6.7-r7"), vulnerable:make_list("lt 2.6.7-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-sources", unaffected:make_list("ge 2.6.4-r4", "lt 2.6"), vulnerable:make_list("lt 2.6.4-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/uclinux-sources", unaffected:make_list("ge 2.6.7_p0-r1", "lt 2.6"), vulnerable:make_list("lt 2.6.7_p0"))) flag++;
if (qpkg_check(package:"sys-kernel/aa-sources", unaffected:make_list("ge 2.6.5-r5", "lt 2.6"), vulnerable:make_list("lt 2.6.5-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/pegasos-dev-sources", unaffected:make_list("ge 2.6.7-r1"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/rsbac-dev-sources", unaffected:make_list("ge 2.6.7-r1"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/usermode-sources", unaffected:make_list("ge 2.6.6-r2", "lt 2.6"), vulnerable:make_list("lt 2.6.6-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/ck-sources", unaffected:make_list("ge 2.6.7-r2", "lt 2.6"), vulnerable:make_list("lt 2.6.7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/win4lin-sources", unaffected:make_list("ge 2.6.7-r1", "lt 2.6"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/mm-sources", unaffected:make_list("ge 2.6.7-r4", "lt 2.6"), vulnerable:make_list("lt 2.6.7-r4"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Linux Kernel");
}
