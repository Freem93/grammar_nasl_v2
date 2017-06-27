#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-fd133d52cc.
#

include("compat.inc");

if (description)
{
  script_id(89469);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/04 16:10:31 $");

  script_cve_id("CVE-2015-7687");
  script_xref(name:"FEDORA", value:"2015-fd133d52cc");

  script_name(english:"Fedora 22 : opensmtpd-5.7.3p1-1.fc22 (2015-fd133d52cc)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Issues fixed in this release (since 5.7.2): - fix an mda buffer
truncation bug which allows a user to create forward files that pass
session checks but fail delivery later down the chain, within the user
mda; - fix remote buffer overflow in unprivileged pony process; -
reworked offline enqueue to better protect against hardlink attacks.
---- Several vulnerabilities have been fixed in OpenSMTPD 5.7.2: - an
oversight in the portable version of fgetln() that allows attackers to
read and write out-of-bounds memory; - multiple denial-of- service
vulnerabilities that allow local users to kill or hang OpenSMTPD; - a
stack-based buffer overflow that allows local users to crash
OpenSMTPD, or execute arbitrary code as the non-chrooted _smtpd user;
- a hardlink attack (or race-conditioned symlink attack) that allows
local users to unset the chflags() of arbitrary files; - a hardlink
attack that allows local users to read the first line of arbitrary
files (for example, root's hash from /etc/master.passwd); - a
denial-of-service vulnerability that allows remote attackers to fill
OpenSMTPD's queue or mailbox hard-disk partition; - an out- of-bounds
memory read that allows remote attackers to crash OpenSMTPD, or leak
information and defeat the ASLR protection; - a use-after-free
vulnerability that allows remote attackers to crash OpenSMTPD, or
execute arbitrary code as the non-chrooted _smtpd user; Further
details can be found in Qualys' audit report:
http://seclists.org/oss-sec/2015/q4/17 MITRE has assigned one CVE for
the use-after-free vulnerability; additional CVEs may be assigned:
http://seclists.org/oss-sec/2015/q4/23 External References:
https://www.opensmtpd.org/announces/release-5.7.2.txt
http://seclists.org/oss- sec/2015/q4/17

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2015/q4/17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2015/q4/23"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1268509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1268794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1268837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1268857"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-October/169600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?652a6f03"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.opensmtpd.org/announces/release-5.7.2.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected opensmtpd package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:opensmtpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"opensmtpd-5.7.3p1-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensmtpd");
}
