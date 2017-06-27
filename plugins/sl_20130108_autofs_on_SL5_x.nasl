#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63591);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/02/26 11:49:26 $");

  script_cve_id("CVE-2012-2697");

  script_name(english:"Scientific Linux Security Update : autofs on SL5.x i386/x86_64");
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
"A bug fix included in SLBA-2012:0264 introduced a denial of service
flaw in autofs. When using autofs with LDAP, a local user could use
this flaw to crash autofs, preventing future mount requests from being
processed until the autofs service was restarted. Note: This flaw did
not impact existing mounts (except for preventing mount expiration).
(CVE-2012-2697)

This update also fixes the following bugs :

  - The autofs init script sometimes timed out waiting for
    the automount daemon to exit and returned a shutdown
    failure if the daemon failed to exit in time. To resolve
    this problem, the amount of time that the init script
    waits for the daemon has been increased to allow for
    cases where servers are slow to respond or there are
    many active mounts.

  - Due to an omission when backporting a change, autofs
    attempted to download the entire LDAP map at startup.
    This mistake has now been corrected.

  - A function to check the validity of a mount location was
    meant to check only for a small subset of map location
    errors. A recent modification in error reporting
    inverted a logic test in this validating function.
    Consequently, the scope of the test was widened, which
    caused the automount daemon to report false positive
    failures. With this update, the faulty logic test has
    been corrected and false positive failures no longer
    occur.

  - When there were many attempts to access invalid or
    non-existent keys, the automount daemon used excessive
    CPU resources. As a consequence, systems sometimes
    became unresponsive. The code has been improved so that
    automount checks for invalid keys earlier in the process
    which has eliminated a significant amount of the
    processing overhead.

  - The auto.master(5) man page did not document the '-t,
    --timeout' option in the FORMAT options section. This
    update adds this information to the man page.

This update also adds the following enhancement :

  - Previously, it was not possible to configure separate
    timeout values for individual direct map entries in the
    autofs master map. This update adds this functionality."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=2563
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f706ba1f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs and / or autofs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (rpm_check(release:"SL5", reference:"autofs-5.0.1-0.rc2.177.el5")) flag++;
if (rpm_check(release:"SL5", reference:"autofs-debuginfo-5.0.1-0.rc2.177.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
