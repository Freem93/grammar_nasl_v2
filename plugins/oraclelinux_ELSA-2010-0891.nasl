#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0891 and 
# Oracle Linux Security Advisory ELSA-2010-0891 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68144);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:49:14 $");

  script_cve_id("CVE-2010-3316", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-4707", "CVE-2010-4708");
  script_bugtraq_id(42472, 43487, 44590);
  script_osvdb_id(68992, 68993, 68994);
  script_xref(name:"RHSA", value:"2010:0891");

  script_name(english:"Oracle Linux 6 : pam (ELSA-2010-0891)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0891 :

Updated pam packages that fix three security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Pluggable Authentication Modules (PAM) provide a system whereby
administrators can set up authentication policies without having to
recompile programs that handle authentication.

It was discovered that the pam_namespace module executed the external
script namespace.init with an unchanged environment inherited from an
application calling PAM. In cases where such an environment was
untrusted (for example, when pam_namespace was configured for setuid
applications such as su or sudo), a local, unprivileged user could
possibly use this flaw to escalate their privileges. (CVE-2010-3853)

It was discovered that the pam_env and pam_mail modules used root
privileges while accessing user's files. A local, unprivileged user
could use this flaw to obtain information, from the lines that have
the KEY=VALUE format expected by pam_env, from an arbitrary file.
Also, in certain configurations, a local, unprivileged user using a
service for which the pam_mail module was configured for, could use
this flaw to obtain limited information about files or directories
that they do not have access to. (CVE-2010-3435)

Note: As part of the fix for CVE-2010-3435, this update changes the
default value of pam_env's configuration option user_readenv to 0,
causing the module to not read user's ~/.pam_environment configuration
file by default, as reading it may introduce unexpected changes to the
environment of the service using PAM, or PAM modules consulted after
pam_env.

It was discovered that the pam_xauth module did not verify the return
values of the setuid() and setgid() system calls. A local,
unprivileged user could use this flaw to execute the xauth command
with root privileges and make it read an arbitrary input file.
(CVE-2010-3316)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for reporting the CVE-2010-3435 issue.

All pam users should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001841.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pam packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"pam-1.1.1-4.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"pam-devel-1.1.1-4.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam / pam-devel");
}
