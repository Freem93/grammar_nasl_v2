#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200907-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39779);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/13 14:12:00 $");

  script_cve_id("CVE-2009-0282");
  script_osvdb_id(53551);
  script_xref(name:"GLSA", value:"200907-08");

  script_name(english:"GLSA-200907-08 : Multiple Ralink wireless drivers: Execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200907-08
(Multiple Ralink wireless drivers: Execution of arbitrary code)

    Aviv reported an integer overflow in multiple Ralink wireless card
    drivers when processing a probe request packet with a long SSID,
    possibly related to an integer signedness error.
  
Impact :

    A physically proximate attacker could send specially crafted packets to
    a user who has wireless networking enabled, possibly resulting in the
    execution of arbitrary code with root privileges.
  
Workaround :

    Unload the kernel modules."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200907-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All external kernel modules have been masked and we recommend that
    users unmerge those drivers. The Linux mainline kernel has equivalent
    support for these devices and the vulnerability has been resolved in
    stable versions of sys-kernel/gentoo-sources.
    # emerge --unmerge 'net-wireless/rt2400'
    # emerge --unmerge 'net-wireless/rt2500'
    # emerge --unmerge 'net-wireless/rt2570'
    # emerge --unmerge 'net-wireless/rt61'
    # emerge --unmerge 'net-wireless/ralink-rt61'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ralink-rt61");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rt2400");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rt2500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rt2570");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rt61");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-wireless/rt61", unaffected:make_list(), vulnerable:make_list("le 1.1.0_beta2"))) flag++;
if (qpkg_check(package:"net-wireless/rt2570", unaffected:make_list(), vulnerable:make_list("le 20070209"))) flag++;
if (qpkg_check(package:"net-wireless/rt2400", unaffected:make_list(), vulnerable:make_list("le 1.2.2_beta3"))) flag++;
if (qpkg_check(package:"net-wireless/rt2500", unaffected:make_list(), vulnerable:make_list("le 1.1.0_pre2007071515"))) flag++;
if (qpkg_check(package:"net-wireless/ralink-rt61", unaffected:make_list(), vulnerable:make_list("le 1.1.1.0"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Multiple Ralink wireless drivers");
}
