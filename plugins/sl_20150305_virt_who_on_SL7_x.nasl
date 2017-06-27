#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82261);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/26 13:38:48 $");

  script_cve_id("CVE-2014-0189");

  script_name(english:"Scientific Linux Security Update : virt-who on SL7.x (noarch)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the /etc/sysconfig/virt-who configuration file,
which may contain hypervisor authentication credentials, was world-
readable. A local user could use this flaw to obtain authentication
credentials from this file. (CVE-2014-0189)

The virt-who package has been upgraded to upstream version 0.11, which
provides a number of bug fixes and enhancements over the previous
version. The most notable bug fixes and enhancements include :

  - Support for remote libvirt.

  - A fix for using encrypted passwords.

  - Bug fixes and enhancements that increase the stability
    of virt-who.

This update also fixes the following bugs :

  - Prior to this update, the virt-who agent failed to read
    the list of virtual guests provided by the VDSM daemon.
    As a consequence, when in VDSM mode, the virt-who agent
    was not able to send updates about virtual guests to
    Subscription Asset Manager (SAM) and Satellite. With
    this update, the agent reads the list of guests when in
    VDSM mode correctly and reports to SAM and Satellite as
    expected.

  - Previously, virt-who used incorrect information when
    connecting to Satellite 5. Consequently, virt-who could
    not connect to Satellite 5 servers. The incorrect
    parameter has been corrected, and virt- who can now
    successfully connect to Satellite 5.

  - Prior to this update, virt-who did not decode the
    hexadecimal representation of a password before
    decrypting it. As a consequence, the decrypted password
    did not match the original password, and attempts to
    connect using the password failed. virt-who has been
    updated to decode the encrypted password and, as a
    result, virt-who now handles storing credentials using
    encrypted passwords as expected.

In addition, this update adds the following enhancement :

  - With this update, virt-who is able to read the list of
    guests from a remote libvirt hypervisor."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=2764
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3431e5ac"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virt-who package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (rpm_check(release:"SL7", reference:"virt-who-0.11-5.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
