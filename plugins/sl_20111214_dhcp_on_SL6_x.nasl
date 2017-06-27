#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61207);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/09/22 02:32:59 $");

  script_cve_id("CVE-2011-4539");

  script_name(english:"Scientific Linux Security Update : dhcp on SL6.x i386/x86_64");
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
"The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

A denial of service flaw was found in the way the dhcpd daemon handled
DHCP request packets when regular expression matching was used in
'/etc/dhcp/dhcpd.conf'. A remote attacker could use this flaw to crash
dhcpd. (CVE-2011-4539)

Users of DHCP should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing this
update, all DHCP servers will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=3277
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9691354e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/14");
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
if (rpm_check(release:"SL6", reference:"dhclient-4.1.1-25.P1.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-4.1.1-25.P1.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-common-4.1.1-25.P1.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-debuginfo-4.1.1-25.P1.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-devel-4.1.1-25.P1.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
