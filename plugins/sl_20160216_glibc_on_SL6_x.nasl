#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(88797);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-7547");
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053");

  script_name(english:"Scientific Linux Security Update : glibc on SL6.x i386/x86_64");
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
"A stack-based buffer overflow was found in the way the libresolv
library performed dual A/AAAA DNS queries. A remote attacker could
create a specially crafted DNS response which could cause libresolv to
crash or, potentially, execute code with the permissions of the user
running the library. Note: this issue is only exposed when libresolv
is called from the nss_dns NSS service module. (CVE-2015-7547)

This update also fixes the following bugs :

  - The dynamic loader has been enhanced to allow the
    loading of more shared libraries that make use of static
    thread local storage. While static thread local storage
    is the fastest access mechanism it may also prevent the
    shared library from being loaded at all since the static
    storage space is a limited and shared process-global
    resource. Applications which would previously fail with
    'dlopen: cannot load any more object with static TLS'
    should now start up correctly.

  - A bug in the POSIX realtime support would cause
    asynchronous I/O or certain timer API calls to fail and
    return errors in the presence of large thread-local
    storage data that exceeded PTHREAD_STACK_MIN in size
    (generally 16 KiB). The bug in librt has been corrected
    and the impacted APIs no longer return errors when large
    thread-local storage data is present in the application."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1602&L=scientific-linux-errata&F=&S=&P=15820
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4669b2c2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.166.el6_7.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
