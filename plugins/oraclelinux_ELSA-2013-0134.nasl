#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0134 and 
# Oracle Linux Security Advisory ELSA-2013-0134 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68705);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2011-4966");
  script_bugtraq_id(55483);
  script_osvdb_id(89032);
  script_xref(name:"RHSA", value:"2013:0134");

  script_name(english:"Oracle Linux 5 : freeradius2 (ELSA-2013-0134)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0134 :

Updated freeradius2 packages that fix one security issue and multiple
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

FreeRADIUS is an open source Remote Authentication Dial-In User
Service (RADIUS) server which allows RADIUS clients to perform
authentication against the RADIUS server. The RADIUS server may
optionally perform accounting of its operations using the RADIUS
protocol.

It was found that the 'unix' module ignored the password expiration
setting in '/etc/shadow'. If FreeRADIUS was configured to use this
module for user authentication, this flaw could allow users with an
expired password to successfully authenticate, even though their
access should have been denied. (CVE-2011-4966)

This update also fixes the following bugs :

* After log rotation, the freeradius logrotate script failed to reload
the radiusd daemon and log messages were lost. This update has added a
command to the freeradius logrotate script to reload the radiusd
daemon and the radiusd daemon re-initializes and reopens its log files
after log rotation as expected. (BZ#787111)

* The radtest script with the 'eap-md5' option failed because it
passed the IP family argument when invoking the radeapclient utility
and the radeapclient utility did not recognize the IP family. The
radeapclient utility now recognizes the IP family argument and radtest
now works with eap-md5 as expected. (BZ#846476)

* Previously, freeradius was compiled without the '--with-udpfromto'
option. Consequently, with a multihomed server and explicitly
specifying the IP address, freeradius sent the reply with the wrong IP
source address. With this update, freeradius has been built with the
'--with-udpfromto' configuration option and the RADIUS reply is always
sourced from the IP address the request was sent to. (BZ#846471)

* Due to invalid syntax in the PostgreSQL admin schema file, the
FreeRADIUS PostgreSQL tables failed to be created. With this update,
the syntax has been adjusted and the tables are created as expected.
(BZ#818885)

* FreeRADIUS has a thread pool that dynamically grows based on load.
If multiple threads using the 'rlm_perl()' function are spawned in
quick succession, the FreeRADIUS server sometimes terminated
unexpectedly with a segmentation fault due to parallel calls to the
'rlm_perl_clone()' function. With this update, a mutex for the threads
has been added and the problem no longer occurs. (BZ#846475)

* The man page for 'rlm_dbm_parser' was incorrectly installed as
'rlm_dbm_parse', omitting the trailing 'r'. The man page now correctly
appears as rlm_dbm_parser. (BZ#781877)

All users of freeradius2 are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
They are also advised to check for RPM backup files ending in
'.rpmnew' or '.rpmsave' under the /etc/raddb/ directory after the
update because the FreeRADIUS server will attempt to load every file
it finds in its configuration directory. The extra files will often
cause the wrong configuration values to be applied resulting in either
unpredictable behavior or the failure of the server to initialize and
run."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003194.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"freeradius2-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-krb5-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-ldap-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-mysql-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-perl-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-postgresql-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-python-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-unixODBC-2.1.12-5.el5")) flag++;
if (rpm_check(release:"EL5", reference:"freeradius2-utils-2.1.12-5.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius2 / freeradius2-krb5 / freeradius2-ldap / etc");
}
