#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60762);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2008-3279");

  script_name(english:"Scientific Linux Security Update : brltty on SL5.x i386/x86_64");
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
"It was discovered that a brltty library had an insecure relative RPATH
(runtime library search path) set in the ELF (Executable and Linking
Format) header. A local user able to convince another user to run an
application using brltty in an attacker-controlled directory, could
run arbitrary code with the privileges of the victim. (CVE-2008-3279)

These updated packages also provide fixes for the following bugs :

  - the brltty configuration file is documented in the
    brltty manual page, but there is no separate manual page
    for the /etc/brltty.conf configuration file: running
    'man brltty.conf' returned 'No manual entry for
    brltty.conf' rather than opening the brltty manual
    entry. This update adds brltty.conf.5 as an alias to the
    brltty manual page. Consequently, running 'man
    brltty.conf' now opens the manual entry documenting the
    brltty.conf specification. (BZ#530554)

  - previously, the brltty-pm.conf configuration file was
    installed in the /etc/brltty/ directory. This file,
    which configures Papenmeier Braille Terminals for use
    with Scientific Linux, is optional. As well, it did not
    come with a corresponding manual page. With this update,
    the file has been moved to
    /usr/share/doc/brltty-3.7.2/BrailleDrivers/Papenmeier/.
    This directory also includes a README document that
    explains the file's purpose and format. (BZ#530554)

  - during the brltty packages installation, the message

    Creating screen inspection device /dev/vcsa...done.

was presented at the console. This was inadequate, especially during
the initial install of the system. These updated packages do not send
any message to the console during installation. (BZ#529163)

  - although brltty contains ELF objects, the
    brltty-debuginfo package was empty. With this update,
    the -debuginfo package contains valid debugging
    information as expected. (BZ#500545)

  - the MAX_NR_CONSOLES definition was acquired by brltty by
    #including linux/tty.h in Programs/api_client.c.
    MAX_NR_CONSOLES has since moved to linux/vt.h but the
    #include in api_client.c was not updated. Consequently,
    brltty could not be built from the source RPM against
    the Scientific Linux 5 kernel. This update corrects the
    #include in api_client.c to linux/vt.h and brltty now
    builds from source as expected. (BZ#456247)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=2402
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a1df6ec"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=456247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530554"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected brlapi, brlapi-devel and / or brltty packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
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
if (rpm_check(release:"SL5", reference:"brlapi-0.4.1-4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"brlapi-devel-0.4.1-4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"brltty-3.7.2-4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
