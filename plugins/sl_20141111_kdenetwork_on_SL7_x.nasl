#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(79229);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/13 12:11:52 $");

  script_cve_id("CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");

  script_name(english:"Scientific Linux Security Update : kdenetwork on SL7.x x86_64");
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
"A NULL pointer dereference flaw was found in the way LibVNCServer
handled certain ClientCutText message. A remote attacker could use
this flaw to crash the VNC server by sending a specially crafted
ClientCutText message from a VNC client. (CVE-2014-6053)

A divide-by-zero flaw was found in the way LibVNCServer handled the
scaling factor when it was set to '0'. A remote attacker could use
this flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6054)

Two stack-based buffer overflow flaws were found in the way
LibVNCServer handled file transfers. A remote attacker could use this
flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6055)

Note: Prior to this update, the kdenetwork packages used an embedded
copy of the LibVNCServer library. With this update, the kdenetwork
packages have been modified to use the system LibVNCServer packages.
Therefore, the update provided by SLSA-2014:1826 must be installed to
fully address the issues in krfb described above.

All running instances of the krfb server must be restarted for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=2944
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26133f29"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"kdenetwork-common-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-debuginfo-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"kdenetwork-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-fileshare-samba-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kdnssd-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kget-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kget-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kopete-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kopete-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kopete-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krdc-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krdc-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krdc-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krfb-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krfb-libs-4.10.5-8.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
