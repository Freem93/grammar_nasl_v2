#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60882);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-3316", "CVE-2010-3435", "CVE-2010-3853");

  script_name(english:"Scientific Linux Security Update : pam on SL5.x i386/x86_64");
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
"It was discovered that the pam_namespace module executed the external
script namespace.init with an unchanged environment inherited from an
application calling PAM. In cases where such an environment was
untrusted (for example, when pam_namespace was configured for setuid
applications such as su or sudo), a local, unprivileged user could
possibly use this flaw to escalate their privileges. (CVE-2010-3853)

It was discovered that the pam_mail module used root privileges while
accessing users' files. In certain configurations, a local,
unprivileged user could use this flaw to obtain limited information
about files or directories that they do not have access to.
(CVE-2010-3435)

It was discovered that the pam_xauth module did not verify the return
values of the setuid() and setgid() system calls. A local,
unprivileged user could use this flaw to execute the xauth command
with root privileges and make it read an arbitrary input file.
(CVE-2010-3316)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1011&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edb56f28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pam and / or pam-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/01");
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
if (rpm_check(release:"SL5", reference:"pam-0.99.6.2-6.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"pam-devel-0.99.6.2-6.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
