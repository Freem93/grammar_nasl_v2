#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61009);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-1011");

  script_name(english:"Scientific Linux Security Update : policycoreutils on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The policycoreutils packages contain the core utilities that are
required for the basic operation of a Security-Enhanced Linux
(SELinux) system and its policies.

It was discovered that the seunshare utility did not enforce proper
file permissions on the directory used as an alternate temporary
directory mounted as /tmp/. A local user could use this flaw to
overwrite files or, possibly, execute arbitrary code with the
privileges of a setuid or setgid application that relies on proper
/tmp/ permissions, by running that application via seunshare.
(CVE-2011-1011)

This update also introduces the following changes :

  - The seunshare utility was moved from the main
    policycoreutils subpackage to the
    policycoreutils-sandbox subpackage. This utility is only
    required by the sandbox feature and does not need to be
    installed by default.

  - Updated selinux-policy packages that add the SELinux
    policy changes required by the seunshare fixes.

All policycoreutils users should upgrade to these updated packages,
which correct this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=448
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2844143"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"policycoreutils-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-gui-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-newrole-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-python-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-sandbox-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-3.7.19-54.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-doc-3.7.19-54.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-minimum-3.7.19-54.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-mls-3.7.19-54.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-targeted-3.7.19-54.el6_0.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
