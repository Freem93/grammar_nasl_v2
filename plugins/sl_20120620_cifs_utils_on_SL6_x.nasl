#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61338);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/29 11:06:16 $");

  script_cve_id("CVE-2012-1586");

  script_name(english:"Scientific Linux Security Update : cifs-utils on SL6.x i386/x86_64");
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
"The cifs-utils package contains tools for mounting and managing shares
on Linux using the SMB/CIFS protocol. The CIFS shares can be used as
standard Linux file systems.

A file existence disclosure flaw was found in mount.cifs. If the tool
was installed with the setuid bit set, a local attacker could use this
flaw to determine the existence of files or directories in directories
not accessible to the attacker. (CVE-2012-1586)

Note: mount.cifs from the cifs-utils package distributed by Scientific
Linux does not have the setuid bit set. We recommend that
administrators do not manually set the setuid bit for mount.cifs.

This update also fixes the following bugs :

  - The cifs.mount(8) manual page was previously missing
    documentation for several mount options. With this
    update, the missing entries have been added to the
    manual page.

  - Previously, the mount.cifs utility did not properly
    update the '/etc/mtab' system information file when
    remounting an existing CIFS mount. Consequently,
    mount.cifs created a duplicate entry of the existing
    mount entry. This update adds the del_mtab() function to
    cifs.mount, which ensures that the old mount entry is
    removed from '/etc/mtab' before adding the updated mount
    entry.

  - The mount.cifs utility did not properly convert user and
    group names to numeric UIDs and GIDs. Therefore, when
    the 'uid', 'gid' or 'cruid' mount options were specified
    with user or group names, CIFS shares were mounted with
    default values. This caused shares to be inaccessible to
    the intended users because UID and GID is set to '0' by
    default. With this update, user and group names are
    properly converted so that CIFS shares are now mounted
    with specified user and group ownership as expected.

  - The cifs.upcall utility did not respect the
    'domain_realm' section in the 'krb5.conf' file and
    worked only with the default domain. Consequently, an
    attempt to mount a CIFS share from a different than the
    default domain failed with the following error message :

    mount error(126): Required key not available

This update modifies the underlying code so that cifs.upcall handles
multiple Kerberos domains correctly and CIFS shares can now be mounted
as expected in a multi-domain environment.

In addition, this update adds the following enhancements :

  - The cifs.upcall utility previously always used the
    '/etc/krb5.conf' file regardless of whether the user had
    specified a custom Kerberos configuration file. This
    update adds the '--krb5conf' option to cifs.upcall
    allowing the administrator to specify an alternate
    krb5.conf file. For more information on this option,
    refer to the cifs.upcall(8) manual page.

  - The cifs.upcall utility did not optimally determine the
    correct service principal name (SPN) used for Kerberos
    authentication, which occasionally caused krb5
    authentication to fail when mounting a server's
    unqualified domain name. This update improves
    cifs.upcall so that the method used to determine the SPN
    is now more versatile.

  - This update adds the 'backupuid' and 'backupgid' mount
    options to the mount.cifs utility. When specified, these
    options grant a user or a group the right to access
    files with the backup intent. For more information on
    these options, refer to the mount.cifs(8) manual page.

All users of cifs-utils are advised to upgrade to this updated
package, which contains backported patches to fix these issues and add
these enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=2047
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9d50961"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cifs-utils and / or cifs-utils-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
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
if (rpm_check(release:"SL6", reference:"cifs-utils-4.8.1-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cifs-utils-debuginfo-4.8.1-10.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
