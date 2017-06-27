#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60998);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-0727");

  script_name(english:"Scientific Linux Security Update : gdm on SL6.x i386/x86_64");
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
"The GNOME Display Manager (GDM) provides the graphical login screen,
shown shortly after boot up, log out, and when user-switching.

A race condition flaw was found in the way GDM handled the cache
directories used to store users' dmrc and face icon files. A local
attacker could use this flaw to trick GDM into changing the ownership
of an arbitrary file via a symbolic link attack, allowing them to
escalate their privileges. (CVE-2011-0727)

We would like to thank Sebastian Krahmer of the SuSE Security Team for
reporting this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=10293
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfae23c8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/29");
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
if (rpm_check(release:"SL6", reference:"gdm-2.30.4-21.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"gdm-libs-2.30.4-21.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"gdm-plugin-fingerprint-2.30.4-21.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"gdm-plugin-smartcard-2.30.4-21.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"gdm-user-switch-applet-2.30.4-21.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
