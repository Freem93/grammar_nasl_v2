#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70605);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/25 10:45:51 $");

  script_cve_id("CVE-2013-4242");

  script_name(english:"Scientific Linux Security Update : libgcrypt on SL5.x, SL6.x i386/x86_64");
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
"It was found that GnuPG was vulnerable to the Yarom/Falkner
flush+reload cache side-channel attack on the RSA secret exponent. An
attacker able to execute a process on the logical CPU that shared the
L3 cache with the GnuPG process (such as a different local user or a
user of a KVM guest running on the same host with the kernel same-page
merging functionality enabled) could possibly use this flaw to obtain
portions of the RSA secret key. (CVE-2013-4242)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=2624
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ce70f65"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libgcrypt, libgcrypt-debuginfo and / or
libgcrypt-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libgcrypt-1.4.4-7.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"libgcrypt-debuginfo-1.4.4-7.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"libgcrypt-devel-1.4.4-7.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"libgcrypt-1.4.5-11.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libgcrypt-debuginfo-1.4.5-11.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libgcrypt-devel-1.4.5-11.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
