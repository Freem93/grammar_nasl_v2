#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60511);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2005-0706");

  script_name(english:"Scientific Linux Security Update : gnome-vfs2 on SL3.x, SL4.x i386/x86_64");
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
"A buffer overflow flaw was discovered in the GNOME virtual file system
when handling data returned by CDDB servers. If a user connected to a
malicious CDDB server, an attacker could use this flaw to execute
arbitrary code on the victim's machine. (CVE-2005-0706)

All running GNOME sessions must be restarted for the update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0901&L=scientific-linux-errata&T=0&P=203
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20de66d3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gnome-vfs2, gnome-vfs2-devel and / or
gnome-vfs2-smb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
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
if (rpm_check(release:"SL3", reference:"gnome-vfs2-2.2.5-2E.3.3")) flag++;
if (rpm_check(release:"SL3", reference:"gnome-vfs2-devel-2.2.5-2E.3.3")) flag++;

if (rpm_check(release:"SL4", reference:"gnome-vfs2-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"gnome-vfs2-devel-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"gnome-vfs2-smb-2.8.2-8.7.el4_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
