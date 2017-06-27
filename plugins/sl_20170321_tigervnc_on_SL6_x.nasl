#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99227);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2016-10207", "CVE-2017-5581");

  script_name(english:"Scientific Linux Security Update : tigervnc on SL6.x i386/x86_64");
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
"Security Fix(es) :

  - A denial of service flaw was found in the TigerVNC's
    Xvnc server. A remote unauthenticated attacker could use
    this flaw to make Xvnc crash by terminating the TLS
    handshake process early. (CVE-2016-10207)

  - A buffer overflow flaw, leading to memory corruption,
    was found in TigerVNC viewer. A remote malicious VNC
    server could use this flaw to crash the client vncviewer
    process resulting in denial of service. (CVE-2017-5581)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=5623
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8698c4d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"tigervnc-1.1.0-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tigervnc-debuginfo-1.1.0-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tigervnc-server-1.1.0-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tigervnc-server-applet-1.1.0-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tigervnc-server-module-1.1.0-24.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
