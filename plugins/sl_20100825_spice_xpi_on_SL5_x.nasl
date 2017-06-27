#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60845);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-2792", "CVE-2010-2794");

  script_name(english:"Scientific Linux Security Update : spice-xpi on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The spice-xpi package provides a plug-in that allows the SPICE client
to run from within Mozilla Firefox.

A race condition was found in the way the SPICE Firefox plug-in and
the SPICE client communicated. A local attacker could use this flaw to
trick the plug-in and the SPICE client into communicating over an
attacker-controlled socket, possibly gaining access to authentication
details, or resulting in a man-in-the-middle attack on the SPICE
connection. (CVE-2010-2792)

It was found that the SPICE Firefox plug-in used a predictable name
for its log file. A local attacker could use this flaw to conduct a
symbolic link attack, allowing them to overwrite arbitrary files
accessible to the user running Firefox. (CVE-2010-2794)

This update also fixes the following bugs :

  - a bug prevented users of Red Hat Enterprise Linux 5.5,
    with all updates applied, from running the SPICE Firefox
    plug-in when using Firefox 3.6.4. With this update, the
    plug-in works correctly with Firefox 3.6.4 and the
    latest version in Red Hat Enterprise Linux 5.5, Firefox
    3.6.7. (BZ#618244)

  - unused code has been removed during source code
    refactoring. This also resolves a bug in the SPICE
    Firefox plug-in that caused it to close random file
    descriptors. (BZ#594006, BZ#619067)

Note: This update should be installed together with the qspice-client
security update.

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=2638
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e0e143f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=594006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=618244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=619067"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-xpi package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/25");
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
if (rpm_check(release:"SL5", reference:"spice-xpi-2.2-2.3.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
