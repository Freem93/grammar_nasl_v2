#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60771);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2009-3767");

  script_name(english:"Scientific Linux Security Update : openldap on SL5.x i386/x86_64");
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
"A flaw was found in the way OpenLDAP handled NUL characters in the
CommonName field of X.509 certificates. An attacker able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority could trick applications using OpenLDAP libraries into
accepting it by mistake, allowing the attacker to perform a
man-in-the-middle attack. (CVE-2009-3767)

This update also fixes the following bugs :

  - the ldap init script did not provide a way to alter
    system limits for the slapd daemon. A variable is now
    available in '/etc/sysconfig/ldap' for this option.
    (BZ#527313)

  - applications that use the OpenLDAP libraries to contact
    a Microsoft Active Directory server could crash when a
    large number of network interfaces existed. This update
    implements locks in the OpenLDAP library code to resolve
    this issue. (BZ#510522)

  - when slapd was configured to allow client certificates,
    approximately 90% of connections froze because of a
    large CA certificate file and slapd not checking the
    success of the SSL handshake. (BZ#509230)

  - the OpenLDAP server would freeze for unknown reasons
    under high load. These packages add support for
    accepting incoming connections by new threads, resolving
    the issue. (BZ#507276)

  - the compat-openldap libraries did not list dependencies
    on other libraries, causing programs that did not
    specifically specify the libraries to fail. Detection of
    the Application Binary Interface (ABI) in use on 64-bit
    systems has been added with this update. (BZ#503734)

  - the OpenLDAP libraries caused applications to crash due
    to an unprocessed network timeout. A timeval of -1 is
    now passed when NULL is passed to LDAP. (BZ#495701)

  - slapd could crash on a server under heavy load when
    using rwm overlay, caused by freeing non-allocated
    memory during operation cleanup. (BZ#495628)

  - the ldap init script made a temporary script in '/tmp/'
    and attempted to execute it. Problems arose when '/tmp/'
    was mounted with the noexec option. The temporary script
    is no longer created. (BZ#483356)

  - the ldap init script always started slapd listening on
    ldap:/// even if instructed to listen only on ldaps:///.
    By correcting the init script, a user can now select
    which ports slapd should listen on. (BZ#481003)

  - the slapd manual page did not mention the supported
    options -V and -o. (BZ#468206)

  - slapd.conf had a commented-out option to load the
    syncprov.la module. Once un-commented, slapd crashed at
    start-up because the module had already been statically
    linked to OpenLDAP. This update removes 'moduleload
    syncprov.la' from slapd.conf, which resolves this issue.
    (BZ#466937)

  - the migrate_automount.pl script produced output that was
    unsupported by autofs. This is corrected by updating the
    output LDIF format for automount records. (BZ#460331)

  - the ldap init script uses the TERM signal followed by
    the KILL signal when shutting down slapd. Minimal delay
    between the two signals could cause the LDAP database to
    become corrupted if it had not finished saving its
    state. A delay between the signals has been added via
    the 'STOP_DELAY' option in '/etc/sysconfig/ldap'.
    (BZ#452064)

  - the migrate_passwd.pl migration script had a problem
    when number fields contained only a zero. Such fields
    were considered to be empty, leading to the attribute
    not being set in the LDIF output. The condition in
    dump_shadow_attributes has been corrected to allow for
    the attributes to contain only a zero. (BZ#113857)

  - the migrate_base.pl migration script did not handle
    third level domains correctly, creating a second level
    domain that could not be held by a database with a three
    level base. This is now allowed by modifying the
    migrate_base.pl script to generate only one domain.
    (BZ#104585)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=793
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34237541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=104585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=113857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=460331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=466937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=468206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=481003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=495628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=495701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=507276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=509230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=510522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=527313"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
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
if (rpm_check(release:"SL5", reference:"compat-openldap-2.3.43_2.2.29-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-2.3.43-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-clients-2.3.43-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-devel-2.3.43-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-servers-2.3.43-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-servers-overlays-2.3.43-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-servers-sql-2.3.43-12.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
