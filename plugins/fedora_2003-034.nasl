#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2003-034.
#

include("compat.inc");

if (description)
{
  script_id(13667);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 21:09:30 $");

  script_cve_id("CVE-2003-0963");
  script_xref(name:"FEDORA", value:"2003-034");

  script_name(english:"Fedora Core 1 : lftp (2003-034)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ulf Harnhammar found a remotely-triggerable buffer overflow in lftp.

An attacker could create a carefully crafted directory on a website
such that, if a user connects to that directory using the lftp client
and subsequently issues a 'ls' or 'rels' command, the attacker could
execute arbitrary code on the users machine. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2003-0963 to this issue.

Users of lftp are advised to upgrade to these erratum packages, which
upgrade lftp to a version which is not vulnerable to this issue.

Red Hat would like to thank Ulf Harnhammar for discovering and
alerting us to this issue. 

This update notification is being re-issued to correct the advisory ID
and issue date. The update packages themselves are unchanged.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2003-December/000024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec7e8967"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lftp and / or lftp-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", cpu:"i386", reference:"lftp-2.6.10-1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"lftp-debuginfo-2.6.10-1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lftp / lftp-debuginfo");
}
