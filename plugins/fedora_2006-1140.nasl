#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1140.
#

include("compat.inc");

if (description)
{
  script_id(24040);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_cve_id("CVE-2006-5740");
  script_xref(name:"FEDORA", value:"2006-1140");

  script_name(english:"Fedora Core 6 : wireshark-0.99.4-1.fc6 (2006-1140)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Nov 1 2006 Radek Vokal <rvokal at redhat.com>
    0.99.4-1

    - upgrade to 0.99.4-1, fixes multiple security issues

    - CVE-2006-5468 - The HTTP dissector could dereference a
      NULL pointer.

    - CVE-2006-5469 - The WBXML dissector could crash.

    - CVE-2006-5470 - The LDAP dissector (and possibly
      others) could crash.

    - CVE-2006-4805 - Basic DoS, The XOT dissector could
      attempt to allocate a large amount of memory and
      crash.

    - CVE-2006-4574 - Single byte \0 overflow written onto
      the heap

    - Tue Oct 10 2006 Radek Vokal <rvokal at redhat.com>
      0.99.4-0.pre1

    - upgrade to 0.99.4-0.pre1

    - Fri Aug 25 2006 Radek Vokal <rvokal at redhat.com>
      0.99.3-1

    - upgrade to 0.99.3

    - Wireshark 0.99.3 fixes the following vulnerabilities :

    - the SCSI dissector could crash. Versions affected:
      CVE-2006-4330

    - the IPsec ESP preference parser was susceptible to
      off-by-one errors. CVE-2006-4331

    - a malformed packet could make the Q.2931 dissector use
      up available memory. CVE-2006-4333

    - Tue Jul 18 2006 Radek Vokal <rvokal at redhat.com>
      0.99.2-1

    - upgrade to 0.99.2

    - Wed Jul 12 2006 Jesse Keating <jkeating at redhat.com>
      - 0.99.2-0.pre1.1

    - rebuild

    - Tue Jul 11 2006 Radek Vokal <rvokal at redhat.com>
      0.99.2-0.pre1

    - upgrade to 0.99.2pre1, fixes (#198242)

    - Tue Jun 13 2006 Radek Vokal <rvokal at redhat.com>
      0.99.1-0.pre1

    - spec file changes

    - Fri Jun 9 2006 Radek Vokal <rvokal at redhat.com>
      0.99.1pre1-1

    - initial build for Fedora Core

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-November/000789.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8c5b6ab"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected wireshark, wireshark-debuginfo and / or
wireshark-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
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
if (rpm_check(release:"FC6", reference:"wireshark-0.99.4-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"wireshark-debuginfo-0.99.4-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"wireshark-gnome-0.99.4-1.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-gnome");
}
