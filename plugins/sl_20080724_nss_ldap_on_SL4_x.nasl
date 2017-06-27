#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60452);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2007-5794");

  script_name(english:"Scientific Linux Security Update : nss_ldap on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A race condition was discovered in nss_ldap, which affected certain
applications that make LDAP connections, such as Dovecot. This could
cause nss_ldap to answer a request for information about one user with
the information about a different user. (CVE-2007-5794)

As well, this updated package fixes the following bugs :

  - in certain situations, on Itanium(R) architectures, when
    an application performed an LDAP lookup for a highly
    populated group, for example, containing more than 150
    members, the application crashed, or may have caused a
    segmentation fault. As well, this issue may have caused
    commands, such as 'ls', to return a 'ber_free_buf:
    Assertion' error.

  - when an application enumerated members of a netgroup,
    the nss_ldap module returned a successful status result
    and the netgroup name, even when the netgroup did not
    exist. This behavior was not consistent with other
    modules. In this updated package, nss_ldap no longer
    returns a successful status when the netgroup does not
    exist.

  - in master and slave server environments, with systems
    that were configured to use a read-only directory
    server, if user log in attempts were denied because
    their passwords had expired, and users attempted to
    immediately change their passwords, the replication
    server returned an LDAP referral, instructing the
    pam_ldap module to resissue its request to a different
    server; however, the pam_ldap module failed to do so. In
    these situations, an error such as the following
    occurred :

LDAP password information update failed: Can't contact LDAP server
Insufficient 'write' privilege to the 'userPassword' attribute of
entry [entry]

In this updated package, password changes are allowed when binding
against a slave server, which resolves this issue.

  - when a system used a directory server for naming
    information, and 'nss_initgroups_ignoreusers root' was
    configured in '/etc/ldap.conf', dbus-daemon-1 would
    hang. Running the 'service messagebus start' command did
    not start the service, and it did not fail, which would
    stop the boot process if it was not cancelled.

As well, this updated package upgrades nss_ldap to the version as
shipped with Scientific Linux 5."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=3097
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd550a58"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss_ldap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/24");
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
if (rpm_check(release:"SL4", reference:"nss_ldap-253-5.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
