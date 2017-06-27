#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-15128.
#

include("compat.inc");

if (description)
{
  script_id(86319);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/02 14:33:25 $");

  script_cve_id("CVE-2015-3230");
  script_xref(name:"FEDORA", value:"2015-15128");

  script_name(english:"Fedora 21 : 389-ds-base-1.3.3.13-1.fc21 (2015-15128)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"389-ds-base-1.3.3.13-1.fc21 - release 1.3.3.13 - Ticket 48265 -
Complex filter in a search request doen't work as expected.
(regression) - Ticket 47981

  - COS cache doesn't properly mark vattr cache as invalid
    when there are multiple suffixes - Ticket 48252 -
    db2index creates index entry from deleted records -
    Ticket 48228 - wrong password check if passwordInHistory
    is decreased. - Ticket 48252 - db2index creates index
    entry from deleted records - Ticket 48254 - CLI db2index
    fails with usage errors - Ticket 47831 - remove debug
    logging from retro cl - Ticket 48245 - Man pages and
    help for remove-ds.pl doesn't display '-a' option -
    Ticket 47931 - Fix coverity issues - Ticket 47931 -
    memberOf & retrocl deadlocks - Ticket 48228 - wrong
    password check if passwordInHistory is decreased. -
    Ticket 48215 - update dbverify usage in main.c - Ticket
    48215 - update dbverify usage - Ticket 48215 -
    verify_db.pl doesn't verify DB specified by -a option -
    Ticket 47810 - memberOf plugin not properly rejecting
    updates - Ticket 48231 - logconv autobind handling
    regression caused by 47446 - Ticket 48232 - winsync
    lastlogon attribute not syncing between DS and AD. -
    Ticket 48206 - Crash during retro changelog trimming -
    Ticket 48224 - redux 2 - logconv.pl should handle
    *.tar.xz, *.txz, *.xz log files - Ticket 48226 - In MMR,
    double free coould occur under some special condition -
    Ticket 48224 - redux - logconv.pl should handle
    *.tar.xz, *.txz, *.xz log files - Ticket 48224

  - redux - logconv.pl should handle *.tar.xz, *.txz, *.xz
    log files - Ticket 48224 - logconv.pl should handle
    *.tar.xz, *.txz, *.xz log files - Ticket 48192

  - Individual abandoned simple paged results request has no
    chance to be cleaned up - Ticket 48212 - Dynamic
    nsMatchingRule changes had no effect on the attrinfo
    thus following reindexing, as well. - Ticket 48195 -
    Slow replication when deleting large quantities of
    multi-valued attributes - Ticket 48175 - Avoid using
    regex in ACL if possible

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1232896"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-October/168985.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?647b290f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"389-ds-base-1.3.3.13-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base");
}
