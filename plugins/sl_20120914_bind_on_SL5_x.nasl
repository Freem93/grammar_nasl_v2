#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62172);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-4244");

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
"The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the way BIND handled resource records with a large
RDATA value. A malicious owner of a DNS domain could use this flaw to
create specially crafted DNS resource records, that would cause a
recursive resolver or secondary server to exit unexpectedly with an
assertion failure. (CVE-2012-4244)

This update also fixes the following bug :

  - The bind-chroot-admin script, executed when upgrading
    the bind-chroot package, failed to correctly update the
    permissions of the /var/named/chroot/etc/named.conf
    file. Depending on the permissions of the file, this
    could have prevented named from starting after
    installing package updates. With this update,
    bind-chroot-admin correctly updates the permissions and
    ownership of the file. Users of bind are advised to
    upgrade to these updated packages, which correct these
    issues. After installing the update, the BIND daemon
    (named) will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=2661
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7c86887"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
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
if (rpm_check(release:"SL5", reference:"bind-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.6-20.P1.el5_8.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
