#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(92582);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 14:39:36 $");

  script_cve_id("CVE-2016-2119");

  script_name(english:"Scientific Linux Security Update : samba on SL7.x x86_64");
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
"Security Fix(es) :

  - A flaw was found in the way Samba initiated signed
    DCE/RPC connections. A man-in-the-middle attacker could
    use this flaw to downgrade the connection to not use
    signing and therefore impersonate the server.
    (CVE-2016-2119)

Bug Fix(es) :

  - Previously, the 'net' command in some cases failed to
    join the client to Active Directory (AD) because the
    permissions setting prevented modification of the
    supported Kerberos encryption type LDAP attribute. With
    this update, Samba has been fixed to allow joining an AD
    domain as a user. In addition, Samba now uses the
    machine account credentials to set up the Kerberos
    encryption types within AD for the joined machine. As a
    result, using 'net' to join a domain now works more
    reliably.

  - Previously, the idmap_hash module worked incorrectly
    when it was used together with other modules. As a
    consequence, user and group IDs were not mapped
    properly. A patch has been applied to skip already
    configured modules. Now, the hash module can be used as
    the default idmap configuration back end and IDs are
    resolved correctly."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1607&L=scientific-linux-errata&F=&S=&P=12228
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc8afcbd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"samba-common-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-tools-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-debuginfo-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"samba-pidl-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-python-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-clients-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-modules-4.2.10-7.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
