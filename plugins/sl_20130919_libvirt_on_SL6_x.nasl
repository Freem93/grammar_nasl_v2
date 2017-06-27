#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70015);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/06 23:41:36 $");

  script_cve_id("CVE-2013-4296", "CVE-2013-4311");

  script_name(english:"Scientific Linux Security Update : libvirt on SL6.x i386/x86_64");
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
"libvirt invokes the PolicyKit pkcheck utility to handle authorization.
A race condition was found in the way libvirt used this utility,
allowing a local user to bypass intended PolicyKit authorizations or
execute arbitrary commands with root privileges. (CVE-2013-4311)

Note: With this update, libvirt has been rebuilt to communicate with
PolicyKit via a different API that is not vulnerable to the race
condition. The polkit SLSA-2013:1270 advisory must also be installed
to fix the CVE-2013-4311 issue.

An invalid free flaw was found in libvirtd's
remoteDispatchDomainMemoryStats function. An attacker able to
establish a read-only connection to libvirtd could use this flaw to
crash libvirtd. (CVE-2013-4296)

This update also fixes the following bugs :

  - Prior to this update, the libvirtd daemon leaked memory
    in the virCgroupMoveTask() function. A fix has been
    provided which prevents libvirtd from incorrect
    management of memory allocations.

  - Previously, the libvirtd daemon was accessing one byte
    before the array in the virCgroupGetValueStr() function.
    This bug has been fixed and libvirtd now stays within
    the array bounds.

  - When migrating, libvirtd leaked the migration URI
    (Uniform Resource Identifier) on destination. A patch
    has been provided to fix this bug and the migration URI
    is now freed correctly.

  - Updating a network interface using
    virDomainUpdateDeviceFlags API failed when a boot order
    was set for that interface. The update failed even if
    the boot order was set in the provided device XML. The
    virDomainUpdateDeviceFlags API has been fixed to
    correctly parse the boot order specification from the
    provided device XML and updating network interfaces with
    boot orders now works as expected.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1309&L=scientific-linux-errata&T=0&P=1580
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?120a12bc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
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
if (rpm_check(release:"SL6", reference:"libvirt-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-debuginfo-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.10.2-18.el6_4.14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
