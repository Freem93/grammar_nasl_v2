#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(66371);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/10 10:51:28 $");

  script_cve_id("CVE-2012-5532");

  script_name(english:"Scientific Linux Security Update : hypervkvpd on SL5.x i386/x86_64");
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
"A denial of service flaw was found in the way hypervkvpd processed
certain Netlink messages. A local, unprivileged user in a guest
(running on Microsoft Hyper-V) could send a Netlink message that, when
processed, would cause the guest's hypervkvpd daemon to exit.
(CVE-2012-5532)

This update also fixes the following bug :

  - The hypervkvpd daemon did not close the file descriptors
    for pool files when they were updated. This could
    eventually lead to hypervkvpd crashing with a 'KVP:
    Failed to open file, pool: 1' error after consuming all
    available file descriptors. With this update, the file
    descriptors are closed, correcting this issue.

After installing the update, it is recommended to reboot all guest
machines."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1305&L=scientific-linux-errata&T=0&P=303
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?137b9bf7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hypervkvpd and / or hypervkvpd-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"hypervkvpd-0-0.7.el5_9.3")) flag++;
if (rpm_check(release:"SL5", reference:"hypervkvpd-debuginfo-0-0.7.el5_9.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
