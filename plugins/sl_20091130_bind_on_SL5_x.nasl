#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60697);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 00:00:32 $");

  script_cve_id("CVE-2009-4022");

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
"CVE-2009-4022 bind: cache poisoning using not validated DNSSEC
responses

Michael Sinatra discovered that BIND was incorrectly caching responses
without performing proper DNSSEC validation, when those responses were
received during the resolution of a recursive client query that
requested DNSSEC records but indicated that checking should be
disabled. A remote attacker could use this flaw to bypass the DNSSEC
validation check and perform a cache poisoning attack if the target
BIND server was receiving such client queries. (CVE-2009-4022)

After installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0912&L=scientific-linux-errata&T=0&P=320
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ac69464"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/30");
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
if (rpm_check(release:"SL5", reference:"bind-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.6-4.P1.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
