#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(77017);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/25 05:40:36 $");

  script_cve_id("CVE-2014-3560");

  script_name(english:"Scientific Linux Security Update : samba4 on SL6.x i386/x86_64");
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
"A heap-based buffer overflow flaw was found in Samba's NetBIOS message
block daemon (nmbd). An attacker on the local network could use this
flaw to send specially crafted packets that, when processed by nmbd,
could possibly lead to arbitrary code execution with root privileges.
(CVE-2014-3560)

After installing this update, the smb service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1408&L=scientific-linux-errata&T=0&P=316
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb378f79"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"samba4-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-client-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-common-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-libs-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-debuginfo-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-devel-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-libs-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-pidl-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-python-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-swat-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-test-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-clients-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-krb5-locator-4.0.0-63.el6_5.rc4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
