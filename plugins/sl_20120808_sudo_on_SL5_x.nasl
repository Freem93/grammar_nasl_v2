#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61456);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/09 10:47:09 $");

  script_cve_id("CVE-2012-3440");

  script_name(english:"Scientific Linux Security Update : sudo on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An insecure temporary file use flaw was found in the sudo package's
post-uninstall script. A local attacker could possibly use this flaw
to overwrite an arbitrary file via a symbolic link attack, or modify
the contents of the '/etc/nsswitch.conf' file during the upgrade or
removal of the sudo package. (CVE-2012-3440)

This update also fixes the following bugs :

  - Previously, sudo escaped non-alphanumeric characters in
    commands using 'sudo -s' or 'sudo -' at the wrong place
    and interfered with the authorization process. Some
    valid commands were not permitted. Now, non-alphanumeric
    characters escape immediately before the command is
    executed and no longer interfere with the authorization
    process. (BZ#844418)

  - Prior to this update, the sudo utility could, under
    certain circumstances, fail to receive the SIGCHLD
    signal when it was executed from a process that blocked
    the SIGCHLD signal. As a consequence, sudo could become
    suspended and fail to exit. This update modifies the
    signal process mask so that sudo can exit and sends the
    correct output. (BZ#844419)

  - The sudo update RHSA-2012:0309 introduced a regression
    that caused the Security-Enhanced Linux (SELinux)
    context of the '/etc/nsswitch.conf' file to change
    during the installation or upgrade of the sudo package.
    This could cause various services confined by SELinux to
    no longer be permitted to access the file. In reported
    cases, this issue prevented PostgreSQL and Postfix from
    starting. (BZ#842759)

  - Updating the sudo package resulted in the 'sudoers' line
    in '/etc/nsswitch.conf' being removed. This update
    corrects the bug in the sudo package's post-uninstall
    script that caused this issue. (BZ#844420)

  - Prior to this update, a race condition bug existed in
    sudo. When a program was executed with sudo, the program
    could possibly exit successfully before sudo started
    waiting for it. In this situation, the program would be
    left in a zombie state and sudo would wait for it
    endlessly, expecting it to still be running. (BZ#844978)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=1240
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad0abd47"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=842759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=844418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=844419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=844420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=844978"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");
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
if (rpm_check(release:"SL5", reference:"sudo-1.7.2p1-14.el5_8.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
