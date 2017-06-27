#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61102);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-2524");

  script_name(english:"Scientific Linux Security Update : libsoup on SL6.x i386/x86_64");
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
"libsoup is an HTTP client/library implementation for GNOME.

A directory traversal flaw was found in libsoup's SoupServer. If an
application used SoupServer to implement an HTTP service, a remote
attacker who is able to connect to that service could use this flaw to
access any local files accessible to that application via a specially
crafted request. (CVE-2011-2524)

All users of libsoup should upgrade to these updated packages, which
contain a backported patch to resolve this issue. All running
applications using libsoup's SoupServer must be restarted for the
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1107&L=scientific-linux-errata&T=0&P=2566
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6f9892c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libsoup, libsoup-debuginfo and / or libsoup-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libsoup-2.28.2-1.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"libsoup-debuginfo-2.28.2-1.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"libsoup-devel-2.28.2-1.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
