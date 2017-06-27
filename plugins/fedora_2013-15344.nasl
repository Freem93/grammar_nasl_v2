#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-15344.
#

include("compat.inc");

if (description)
{
  script_id(69774);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 21:12:42 $");

  script_cve_id("CVE-2012-5533");
  script_bugtraq_id(56619);
  script_xref(name:"FEDORA", value:"2013-15344");

  script_name(english:"Fedora 18 : lighttpd-1.4.32-1.fc18 (2013-15344)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"One important denial of service (in 1.4.31) fix: CVE-2012-5533.

A flaw was found in lighttpd version 1.4.31 that could be exploited by
a remote user to cause a denial of service condition in lighttpd. A
client could send a malformed Connection header to lighttpd (such as
'Connection: TE,,Keep-Alive'), which would cause lighttpd to enter an
endless loop, detecting an empty token but not incrementing the
current string position, causing it to continually read ',' over and
over.

This flaw was introduced in 1.4.31 [1] when an 'invalid read' bug was
fixed [2].

[1]
http://redmine.lighttpd.net/projects/lighttpd/repository/revisions/283
0/diff/ [2] http://redmine.lighttpd.net/issues/2413

Acknowledgement :

Red Hat would like to thank Stefan Buhler for reporting this issue.
Upstream acknowledges Jesse Sipprell from McClatchy Interactive, Inc.
as the original reporter.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://redmine.lighttpd.net/issues/2413"
  );
  # http://redmine.lighttpd.net/projects/lighttpd/repository/revisions/2830/diff/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dec5b23a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=878914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=878915"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115110.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a2db5ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"lighttpd-1.4.32-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd");
}
