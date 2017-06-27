#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64949);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/17 15:50:10 $");

  script_cve_id("CVE-2012-3955");

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
"A flaw was found in the way the dhcpd daemon handled the expiration
time of IPv6 leases. If dhcpd's configuration was changed to reduce
the default IPv6 lease time, lease renewal requests for previously
assigned leases could cause dhcpd to crash. (CVE-2012-3955)

This update also fixes the following bugs :

  - Prior to this update, the DHCP server discovered only
    the first IP address of a network interface if the
    network interface had more than one configured IP
    address. As a consequence, the DHCP server failed to
    restart if the server was configured to serve only a
    subnet of the following IP addresses. This update
    modifies network interface addresses discovery code to
    find all addresses of a network interface. The DHCP
    server can also serve subnets of other addresses.

  - Prior to this update, the dhclient rewrote the
    /etc/resolv.conf file with backup data after it was
    stopped even when the PEERDNS flag was set to 'no'
    before shut down if the configuration file was changed
    while the dhclient ran with PEERDNS=yes. This update
    removes the backing up and restoring functions for this
    configuration file from the dhclient-script. Now, the
    dhclient no longer rewrites the /etc/resolv.conf file
    when stopped.

After installing this update, all DHCP servers will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=4671
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1385294"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"dhclient-4.1.1-34.P1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-4.1.1-34.P1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-common-4.1.1-34.P1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-debuginfo-4.1.1-34.P1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-devel-4.1.1-34.P1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
