#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60824);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-2526");

  script_name(english:"Scientific Linux Security Update : lvm2-cluster,lvm2 for SL5");
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
"It was discovered that the cluster logical volume manager daemon
(clvmd) did not verify the credentials of clients connecting to its
control UNIX abstract socket, allowing local, unprivileged users to
send control commands that were intended to only be available to the
privileged root user. This could allow a local, unprivileged user to
cause clvmd to exit, or request clvmd to activate, deactivate, or
reload any logical volume on the local system or another system in the
cluster. (CVE-2010-2526)

Note: This update changes clvmd to use a pathname-based socket rather
than an abstract socket. As such, the lvm2 update 2010:0569, which
changes LVM to also use this pathname-based socket, must also be
installed for LVM to be able to communicate with the updated clvmd.

All lvm2-cluster users should upgrade to this updated package, which
contains a backported patch to correct this issue. After installing
the updated package, clvmd must be restarted for the update to take
effect.

5. Bugs fixed

CVE-2010-2526 lvm2-cluster: insecurity when communicating between lvm2
and clvmd

6. Package List :"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=3592
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c355c951"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lvm2 and / or lvm2-cluster packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
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
if (rpm_check(release:"SL5", reference:"lvm2-2.02.56-8.el5_5.6")) flag++;
if (rpm_check(release:"SL5", reference:"lvm2-cluster-2.02.56-7.el5_5.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
