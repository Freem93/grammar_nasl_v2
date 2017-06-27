#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87576);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2014-8240", "CVE-2014-8241");

  script_name(english:"Scientific Linux Security Update : tigervnc on SL7.x x86_64");
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
"An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way TigerVNC handled screen sizes. A malicious VNC server
could use this flaw to cause a client to crash or, potentially,
execute arbitrary code on the client. (CVE-2014-8240)

A NULL pointer dereference flaw was found in TigerVNC's XRegion. A
malicious VNC server could use this flaw to cause a client to crash.
(CVE-2014-8241)

The tigervnc packages have been upgraded to upstream version 1.3.1,
which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bug :

  - The position of the mouse cursor in the VNC session was
    not correctly communicated to the VNC viewer, resulting
    in cursor misplacement. The method of displaying the
    remote cursor has been changed, and cursor movements on
    the VNC server are now accurately reflected on the VNC
    client."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=4878
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9452ecd5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-1.3.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-debuginfo-1.3.1-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-icons-1.3.1-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-license-1.3.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-1.3.1-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-server-applet-1.3.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.3.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-module-1.3.1-3.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
