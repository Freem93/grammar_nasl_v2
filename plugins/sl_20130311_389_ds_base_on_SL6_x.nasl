#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65240);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/20 10:49:03 $");

  script_cve_id("CVE-2013-0312");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL6.x i386/x86_64");
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
"A flaw was found in the way LDAPv3 control data was handled by 389
Directory Server. If a malicious user were able to bind to the
directory (even anonymously) and send an LDAP request containing
crafted LDAPv3 control data, they could cause the server to crash,
denying service to the directory. (CVE-2013-0312)

This update also fixes the following bugs :

  - After an upgrade from Scientific Linux 6.3 to version
    6.4, the upgrade script did not update the schema file
    for the PamConfig object class. Consequently, new
    features for PAM such as configuration of multiple
    instances and pamFilter attribute could not be used
    because of the schema violation. With this update, the
    upgrade script updates the schema file for the PamConfig
    object class and new features function properly.

  - Previously, the valgrind test suite reported recurring
    memory leaks in the modify_update_last_modified_attr()
    function. The size of the leaks averaged between 60-80
    bytes per modify call. In environments where modify
    operations were frequent, this caused significant
    problems. Now, memory leaks no longer occur in the
    modify_update_last_modified_attr() function.

  - The Directory Server (DS) failed when multi-valued
    attributes were replaced. The problem occurred when
    replication was enabled, while the server executing the
    modification was configured as a single master and there
    was at least one replication agreement. Consequently,
    the modification requests were refused by the master
    server, which returned a code 20 'Type or value exists'
    error message. These requests were replacements of
    multi-valued attributes, and the error only occurred
    when one of the new values matched one of the current
    values of the attribute, but had a different letter
    case. Now, modification requests function properly and
    no longer return code 20 errors.

  - The DNA (distributed numeric assignment) plug-in, under
    certain conditions, could log error messages with the
    'DB_LOCK_DEADLOCK' error code when attempting to create
    an entry with a uidNumber attribute. Now, DNA handles
    this case properly and errors no longer occur during
    attempts to create entries with uidNumber attributes.

  - Posix Winsync plugin was calling an internal modify
    function which was not necessary. The internal modify
    call failed and logged an error message
    'slapi_modify_internal_set_pb: NULL parameter' which was
    not clear. This patch stops calling the internal modify
    function if it is not necessary and the cryptic error
    message is not observed.

  - Previously, under certain conditions, the dse.ldif file
    had 0 bytes after a server termination or when the
    machine was powered off. Consequently, after the system
    was brought up, a DS or IdM system could be unable to
    restart, leading to production server outages. Now, the
    server mechanism by which the dse.ldif is written is
    more robust, and tries all available backup dse.ldif
    files, and outages no longer occur.

  - Due to an incorrect interpretation of an error code, a
    directory server considered an invalid chaining
    configuration setting as the disk full error and shut
    down unexpectedly. Now, a more appropriate error code is
    in use and the server no longer shuts down from invalid
    chaining configuration settings.

  - While trying to remove a tombstone entry, the ns-slapd
    daemon terminated unexpectedly with a segmentation
    fault. With this update, removal of tombstone entries no
    longer causes crashes.

After installing this update, the 389 server service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=4127
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?827f9bfc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"389-ds-base-1.2.11.15-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-debuginfo-1.2.11.15-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-devel-1.2.11.15-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-libs-1.2.11.15-12.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
