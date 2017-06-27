#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-8915.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47518);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2010-1512");
  script_osvdb_id(64592);
  script_xref(name:"FEDORA", value:"2010-8915");

  script_name(english:"Fedora 11 : aria2-1.9.3-1.fc11 (2010-8915)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu May 20 2010 Rahul Sundaram <sundaram at
    fedoraproject.org> - 1.9.3-1

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=2101

    - Fixes CVE-2010-1512. rhbz # 592014

    - Sat Mar 20 2010 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.9.0-1

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1990

    - Tue Feb 16 2010 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.8.2-1

    - Several bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1860

    - Mon Dec 28 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.8.0-1

    - Many new features including XML RPC improvements and
      other bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1778

    - Mon Dec 7 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.7.1-1

    - Option --bt-prioritize-piece=tail will work again

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1721

    - Wed Nov 4 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.6.3-1

    - Minor bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1616

    - Sat Oct 10 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.6.2-1

    - Minor bug fixes and switch XZ compressed source

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1586

    - Thu Oct 8 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.6.1-1

    - Fixes memory leak in HTTP/FTP downloads and other
      minor bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1569

    - Wed Sep 23 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.6.0-1

    - Minor bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1544

    - Mon Aug 24 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.5.2-1

    - Minor bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1504

    - Sun Jul 26 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.5.1-2

    - update source

    - Sun Jul 26 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.5.1-1

    - Minor bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1494

    - Fixed the license tag

    - Sun Jul 26 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.5.0-1

    - Mostly minor bug fixes

    - WEB-Seeding support for multi-file torrent

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1476

    - Fri Jul 24 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1.3.1-2

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=2101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=592012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041758.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b7fdecd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected aria2 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:aria2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"aria2-1.9.3-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aria2");
}
