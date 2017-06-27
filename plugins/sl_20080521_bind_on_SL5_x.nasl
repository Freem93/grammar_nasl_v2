#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60402);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-6283", "CVE-2008-0122");

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
"It was discovered that the bind packages created the 'rndc.key' file
with insecure file permissions. This allowed any local user to read
the content of this file. A local user could use this flaw to control
some aspects of the named daemon by using the rndc utility, for
example, stopping the named daemon. This problem did not affect
systems with the bind-chroot package installed. (CVE-2007-6283)

A buffer overflow flaw was discovered in the 'inet_network()'
function, as implemented by libbind. An attacker could use this flaw
to crash an application calling this function, with an argument
provided from an untrusted source. (CVE-2008-0122)

As well, these updated packages fix the following bugs :

  - when using an LDAP backend, missing function
    declarations caused segmentation faults, due to stripped
    pointers on machines where pointers are longer than
    integers.

  - starting named may have resulted in named crashing, due
    to a race condition during D-BUS connection
    initialization. This has been resolved in these updated
    packages.

  - the named init script returned incorrect error codes,
    causing the 'status' command to return an incorrect
    status. In these updated packages, the named init script
    is Linux Standard Base (LSB) compliant.

  - in these updated packages, the 'rndc [command] [zone]'
    command, where [command] is an rndc command, and [zone]
    is the specified zone, will find the [zone] if the zone
    is unique to all views.

  - the default named log rotation script did not work
    correctly when using the bind-chroot package. In these
    updated packages, installing bind-chroot creates the
    symbolic link '/var/log/named.log', which points to
    '/var/named/chroot/var/log/named.log', which resolves
    this issue.

  - a previous bind update incorrectly changed the
    permissions on the '/etc/openldap/schema/dnszone.schema'
    file to mode 640, instead of mode 644, which resulted in
    OpenLDAP not being able to start. In these updated
    packages, the permissions are correctly set to mode 644.

  - the 'checkconfig' parameter was missing in the named
    usage report. For example, running the 'service named'
    command did not return 'checkconfig' in the list of
    available options.

  - due to a bug in the named init script not handling the
    rndc return value correctly, the 'service named stop'
    and 'service named restart' commands failed on certain
    systems.

  - the bind-chroot spec file printed errors when running
    the '%pre' and '%post' sections. Errors such as the
    following occurred :

Locating //etc/named.conf failed: [FAILED]

This has been resolved in these updated packages.

  - installing the bind-chroot package creates a
    '/dev/random' file in the chroot environment; however,
    the '/dev/random' file had an incorrect SELinux label.
    Starting named resulted in an 'avc: denied { getattr }
    for pid=[pid] comm='named' path='/dev/random'' error
    being logged. The '/dev/random' file has the correct
    SELinux label in these updated packages.

  - in certain situations, running the 'bind +trace' command
    resulted in random segmentation faults.

As well, these updated packages add the following enhancements :

  - support has been added for GSS-TSIG (RFC 3645).

  - the 'named.root' file has been updated to reflect the
    new address for L.ROOT-SERVERS.NET.

  - updates BIND to the latest 9.3 maintenance release."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=1821
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56f17767"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"bind-9.3.4-6.P1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.4-6.P1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.4-6.P1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.4-6.P1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.4-6.P1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.4-6.P1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.4-6.P1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.4-6.P1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
