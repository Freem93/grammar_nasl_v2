#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60374);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_name(english:"Scientific Linux Security Update : openafs on SL41-45 i386/x86_64");
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
"In pthread-aware fileservers, the 'host_glock' pthread lock, accessed
via the H_LOCK and H_UNLOCK macros, is used to provide safe access to
host structures. This lock is required to be held when updating
information pertaining to a host. The RPC handler for the
GiveUpAllCallBacks RPC did not hold this lock while performing its
work.

This errata is already in SL 4.6. So it only applies to SL 40-45"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0803&L=scientific-linux-errata&T=0&P=1329
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48d182cb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

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
if (rpm_check(release:"SL4", reference:"openafs-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-devel-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-client-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-compat-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-debug-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-devel-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kernel-source-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kpasswd-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-krb5-1.4.6-58.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-server-1.4.6-58.SL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
