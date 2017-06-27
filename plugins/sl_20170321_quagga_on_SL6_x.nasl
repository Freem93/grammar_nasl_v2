#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99223);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2013-2236", "CVE-2016-1245", "CVE-2016-2342", "CVE-2016-4049", "CVE-2017-5495");

  script_name(english:"Scientific Linux Security Update : quagga on SL6.x i386/x86_64");
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

  - A stack-based buffer overflow flaw was found in the way
    Quagga handled IPv6 router advertisement messages. A
    remote attacker could use this flaw to crash the zebra
    daemon resulting in denial of service. (CVE-2016-1245)

  - A stack-based buffer overflow flaw was found in the way
    the Quagga BGP routing daemon (bgpd) handled Labeled-VPN
    SAFI routes data. A remote attacker could use this flaw
    to crash the bgpd daemon resulting in denial of service.
    (CVE-2016-2342)

  - A denial of service flaw was found in the Quagga BGP
    routing daemon (bgpd). Under certain circumstances, a
    remote attacker could send a crafted packet to crash the
    bgpd daemon resulting in denial of service.
    (CVE-2016-4049)

  - A denial of service flaw affecting various daemons in
    Quagga was found. A remote attacker could use this flaw
    to cause the various Quagga daemons, which expose their
    telnet interface, to crash. (CVE-2017-5495)

  - A stack-based buffer overflow flaw was found in the way
    the Quagga OSPFD daemon handled LSA (link-state
    advertisement) packets. A remote attacker could use this
    flaw to crash the ospfd daemon resulting in denial of
    service. (CVE-2013-2236)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=2144
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3198cd3a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
if (rpm_check(release:"SL6", reference:"quagga-0.99.15-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"quagga-contrib-0.99.15-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"quagga-debuginfo-0.99.15-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"quagga-devel-0.99.15-14.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
