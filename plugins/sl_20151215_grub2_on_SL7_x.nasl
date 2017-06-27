#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87586);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-8370");

  script_name(english:"Scientific Linux Security Update : grub2 on SL7.x x86_64");
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
"A flaw was found in the way the grub2 handled backspace characters
entered in username and password prompts. An attacker with access to
the system console could use this flaw to bypass grub2 password
protection and gain administrative access to the system.
(CVE-2015-8370)

This update also fixes the following bug :

  - When upgrading from Scientific Linux 7.1 and earlier, a
    configured boot password was not correctly migrated to
    the newly introduced user.cfg configuration files. This
    could possibly prevent system administrators from
    changing grub2 configuration during system boot even if
    they provided the correct password. This update corrects
    the password migration script and the incorrectly
    generated user.cfg file."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=19156
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ad0a4c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"grub2-2.02-0.33.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"grub2-debuginfo-2.02-0.33.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"grub2-efi-2.02-0.33.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"grub2-efi-modules-2.02-0.33.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"grub2-tools-2.02-0.33.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
