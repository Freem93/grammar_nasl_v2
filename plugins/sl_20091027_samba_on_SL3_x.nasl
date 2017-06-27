#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60684);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:42:08 $");

  script_cve_id("CVE-2009-1888", "CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");

  script_name(english:"Scientific Linux Security Update : samba on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A denial of service flaw was found in the Samba smbd daemon. An
authenticated, remote user could send a specially crafted response
that would cause an smbd child process to enter an infinite loop. An
authenticated, remote user could use this flaw to exhaust system
resources by opening multiple CIFS sessions. (CVE-2009-2906)

An uninitialized data access flaw was discovered in the smbd daemon
when using the non-default 'dos filemode' configuration option in
'smb.conf'. An authenticated, remote user with write access to a file
could possibly use this flaw to change an access control list for that
file, even when such access should have been denied. (CVE-2009-1888)

A flaw was discovered in the way Samba handled users without a home
directory set in the back-end password database (e.g. '/etc/passwd').
If a share for the home directory of such a user was created (e.g.
using the automated '[homes]' share), any user able to access that
share could see the whole file system, possibly bypassing intended
access restrictions.(CVE-2009-2813)

The mount.cifs program printed CIFS passwords as part of its debug
output when running in verbose mode. When mount.cifs had the setuid
bit set, a local, unprivileged user could use this flaw to disclose
passwords from a file that would otherwise be inaccessible to that
user. Note: mount.cifs from the samba packages distributed by Red Hat
does not have the setuid bit set. This flaw only affected systems
where the setuid bit was manually set by an administrator.
(CVE-2009-2948) This update also fixes the following bug for SL3 :

  - an earlier update added code to escape input passed to
    scripts that are run by Samba. This code was missing 'c'
    from the list of valid characters, causing it to be
    escaped. With this update, the previous patch has been
    updated to include 'c' in the list of valid characters.
    (BZ#242754)

After installing this update, the smb service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=2067
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27b38b2a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=242754"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"samba-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"SL3", reference:"samba-client-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"SL3", reference:"samba-common-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"SL3", reference:"samba-swat-3.0.9-1.3E.16")) flag++;

if (rpm_check(release:"SL4", reference:"samba-3.0.33-0.18.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"samba-client-3.0.33-0.18.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"samba-common-3.0.33-0.18.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"samba-swat-3.0.33-0.18.el4_8")) flag++;

if (rpm_check(release:"SL5", reference:"samba-3.0.33-3.15.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"samba-client-3.0.33-3.15.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"samba-common-3.0.33-3.15.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"samba-swat-3.0.33-3.15.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
