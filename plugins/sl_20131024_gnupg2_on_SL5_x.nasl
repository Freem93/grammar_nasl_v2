#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70603);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/25 10:45:51 $");

  script_cve_id("CVE-2012-6085", "CVE-2013-4351", "CVE-2013-4402");

  script_name(english:"Scientific Linux Security Update : gnupg2 on SL5.x, SL6.x i386/x86_64");
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
"A denial of service flaw was found in the way GnuPG parsed certain
compressed OpenPGP packets. An attacker could use this flaw to send
specially crafted input data to GnuPG, making GnuPG enter an infinite
loop when parsing data. (CVE-2013-4402)

It was found that importing a corrupted public key into a GnuPG
keyring database corrupted that keyring. An attacker could use this
flaw to trick a local user into importing a specially crafted public
key into their keyring database, causing the keyring to be corrupted
and preventing its further use. (CVE-2012-6085)

It was found that GnuPG did not properly interpret the key flags in a
PGP key packet. GPG could accept a key for uses not indicated by its
holder. (CVE-2013-4351)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=2885
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5afdab07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gnupg2, gnupg2-debuginfo and / or gnupg2-smime
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

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
if (rpm_check(release:"SL5", reference:"gnupg2-2.0.10-6.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"gnupg2-debuginfo-2.0.10-6.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"gnupg2-2.0.14-6.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"gnupg2-debuginfo-2.0.14-6.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"gnupg2-smime-2.0.14-6.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
