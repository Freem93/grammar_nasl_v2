#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60920);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3762");

  script_name(english:"Scientific Linux Security Update : bind on SL5.x i386/x86_64");
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
"It was discovered that named did not invalidate previously cached
RRSIG records when adding an NCACHE record for the same entry to the
cache. A remote attacker allowed to send recursive DNS queries to
named could use this flaw to crash named. (CVE-2010-3613)

A flaw was found in the DNSSEC validation code in named. If named had
multiple trust anchors configured for a zone, a response to a request
for a record in that zone with a bad signature could cause named to
crash. (CVE-2010-3762)

It was discovered that, in certain cases, named did not properly
perform DNSSEC validation of an NS RRset for zones in the middle of a
DNSKEY algorithm rollover. This flaw could cause the validator to
incorrectly determine that the zone is insecure and not protected by
DNSSEC. (CVE-2010-3614)

After installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1012&L=scientific-linux-errata&T=0&P=1313
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59a858f8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/13");
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
if (rpm_check(release:"SL5", reference:"bind-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.6-4.P1.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
