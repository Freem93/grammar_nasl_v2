#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85192);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2014-2015");

  script_name(english:"Scientific Linux Security Update : freeradius on SL6.x i386/x86_64");
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
"A stack-based buffer overflow was found in the way the FreeRADIUS
rlm_pap module handled long password hashes. An attacker able to make
radiusd process a malformed password hash could cause the daemon to
crash. (CVE-2014-2015)

The freeradius packages have been upgraded to upstream version 2.2.6,
which provides a number of bug fixes and enhancements over the
previous version, including :

  - The number of dictionaries have been updated.

  - This update implements several Extensible Authentication
    Protocol (EAP) improvements.

  - A number of new expansions have been added, including:
    %{randstr:...}, %{hex:...}, %{sha1:...}, %{base64:...},
    %{tobase64:...}, and %{base64tohex:...}.

  - Hexadecimal numbers (0x...) are now supported in
    %{expr:...} expansions.

  - This update adds operator support to the rlm_python
    module.

  - The Dynamic Host Configuration Protocol (DHCP) and DHCP
    relay code have been finalized.

  - This update adds the rlm_cache module to cache arbitrary
    attributes.

This update also fixes the following bugs :

  - The /var/log/radius/radutmp file was configured to
    rotate at one-month intervals, even though this was
    unnecessary. This update removes /var/log/radius/radutmp
    from the installed logrotate utility configuration in
    the /etc/logrotate.d/radiusd file, and
    /var/log/radius/radutmp is no longer rotated.

  - The radiusd service could not write the output file
    created by the raddebug utility. The raddebug utility
    now sets appropriate ownership to the output file,
    allowing radiusd to write the output.

  - After starting raddebug using the 'raddebug -t 0'
    command, raddebug exited immediately. A typo in the
    special case comparison has been fixed, and raddebug now
    runs for 11.5 days in this situation.

  - MS-CHAP authentication failed when the User-Name and
    MS-CHAP-User-Name attributes used different encodings,
    even when the user provided correct credentials. Now,
    MS-CHAP authentication properly handles mismatching
    character encodings. Authentication with correct
    credentials no longer fails in this situation.

  - Automatically generated default certificates used the
    SHA-1 algorithm message digest, which is considered
    insecure. The default certificates now use the more
    secure SHA-256 algorithm message digest.

  - During the Online Certificate Status Protocol (OCSP)
    validation, radiusd terminated unexpectedly with a
    segmentation fault after attempting to access the next
    update field that was not provided by the OCSP
    responder. Now, radiusd does not crash in this situation
    and instead continues to complete the OCSP validation.

  - Prior to this update, radiusd failed to work with some
    of the more recent MikroTIK attributes, because the
    installed directory.mikrotik file did not include them.
    This update adds MikroTIK attributes with IDs up to 22
    to dictionary.mikrotik, and radiusd now works as
    expected with these attributes.

After installing this update, the radiusd service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=6517
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dda880e3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"freeradius-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-debuginfo-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-krb5-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-ldap-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-mysql-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-perl-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-postgresql-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-python-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-unixODBC-2.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"freeradius-utils-2.2.6-4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
