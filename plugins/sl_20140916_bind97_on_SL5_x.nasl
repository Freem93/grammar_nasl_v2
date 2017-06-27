#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78416);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/12/14 06:22:31 $");

  script_cve_id("CVE-2014-0591");

  script_name(english:"Scientific Linux Security Update : bind97 on SL5.x i386/x86_64");
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
"A denial of service flaw was found in the way BIND handled queries for
NSEC3-signed zones. A remote attacker could use this flaw against an
authoritative name server that served NCES3-signed zones by sending a
specially crafted query, which, when processed, would cause named to
crash. (CVE-2014-0591)

Note: The CVE-2014-0591 issue does not directly affect the version of
bind97 shipped in Scientific Linux 5. This issue is being addressed
however to assure it is not introduced in future builds of bind97
(possibly built with a different compiler or C library optimization).

This update also fixes the following bug :

  - Previously, the bind97 initscript did not check for the
    existence of the ROOTDIR variable when shutting down the
    named daemon. As a consequence, some parts of the file
    system that are mounted when using bind97 in a chroot
    environment were unmounted on daemon shut down, even if
    bind97 was not running in a chroot environment. With
    this update, the initscript has been fixed to check for
    the existence of the ROOTDIR variable when unmounting
    some parts of the file system on named daemon shut down.
    Now, when shutting down bind97 that is not running in a
    chroot environment, no parts of the file system are
    unmounted.

After installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=190
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?048e4fce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"bind97-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-chroot-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-debuginfo-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-devel-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-libs-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-utils-9.7.0-21.P2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
