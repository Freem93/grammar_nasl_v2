#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(81476);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/10 05:42:14 $");

  script_cve_id("CVE-2015-0240");

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
"An uninitialized pointer use flaw was found in the Samba daemon
(smbd). A malicious Samba client could send specially crafted netlogon
packets that, when processed by smbd, could potentially lead to
arbitrary code execution with the privileges of the user running smbd
(by default, the root user). (CVE-2015-0240)

After installing this update, the smb service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1502&L=scientific-linux-errata&T=0&P=1398
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c788722b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
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
if (rpm_check(release:"SL6", reference:"samba4-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-client-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-common-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-libs-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-debuginfo-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-devel-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-libs-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-pidl-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-python-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-swat-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-test-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-clients-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-krb5-locator-4.0.0-66.el6_6.rc4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
