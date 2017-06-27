#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisories ELSA-2006-0726 / 
# ELSA-2006-0658 / ELSA-2006-0602.
#

include("compat.inc");

if (description)
{
  script_id(67418);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2006-3627", "CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632", "CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4333", "CVE-2006-4574", "CVE-2006-4805", "CVE-2006-5468", "CVE-2006-5469", "CVE-2006-5740");
  script_osvdb_id(27360, 27361, 27362, 27363, 27364, 27365, 27366, 27368, 27369, 27370, 27371, 28196, 28197, 28199, 30068, 30069, 30070, 30071, 30072);
  script_xref(name:"RHSA", value:"2006:0602");
  script_xref(name:"RHSA", value:"2006:0658");
  script_xref(name:"RHSA", value:"2006:0726");

  script_name(english:"Oracle Linux 4 : wireshark (ELSA-2006-0726 / ELSA-2006-0658 / ELSA-2006-0602)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Wireshark packages that fix various security vulnerabilities are
now available. 

This update has been rated as having moderate security impact by the Red
Hat Security Response Team. 

Wireshark is a program for monitoring network traffic. 

Users of Wireshark should upgrade to these updated packages containing
Wireshark version 0.99.4, which is not vulnerable to these issues.


From Red Hat Security Advisory 2006:0726 :

Several flaws were found in Wireshark's HTTP, WBXML, LDAP, and XOT
protocol dissectors.  Wireshark could crash or stop responding if it
read a malformed packet off the network.  (CVE-2006-4805, CVE-2006-5468,
CVE-2006-5469, CVE-2006-5740)

A single NULL byte heap based buffer overflow was found in Wireshark's
MIME Multipart dissector.  Wireshark could crash or possibly execute
arbitrary arbitrary code as the user running Wireshark.  (CVE-2006-4574)


From Red Hat Security Advisory 2006:0658 :

Bugs were found in Wireshark's SCSI and SSCOP protocol dissectors. 
Ethereal could crash or stop responding if it read a malformed packet
off the network.  (CVE-2006-4330, CVE-2006-4333)

An off-by-one bug was found in the IPsec ESP decryption preference
parser.  Ethereal could crash or stop responding if it read a malformed
packet off the network.  (CVE-2006-4331)


From Red Hat Security Advisory 2006:0602 :

In May 2006, Ethereal changed its name to Wireshark.  This update
deprecates the Ethereal packages in Red Hat Enterprise Linux 2.1, 3, and
4 in favor of the supported Wireshark packages. 

Several denial of service bugs were found in Ethereal's protocol
dissectors.  It was possible for Ethereal to crash or stop responding if
it read a malformed packet off the network.  (CVE-2006-3627,
CVE-2006-3629, CVE-2006-3631)

Several buffer overflow bugs were found in Ethereal's ANSI MAP, NCP
NMAS, and NDPStelnet dissectors.  It was possible for Ethereal to crash
or execute arbitrary code if it read a malformed packet off the network. 
(CVE-2006-3630, CVE-2006-3632)

Several format string bugs were found in Ethereal's Checkpoint FW-1, MQ,
XML, and NTP dissectors.  It was possible for Ethereal to crash or
execute arbitrary code if it read a malformed packet off the network. 
(CVE-2006-3628)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-December/000026.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected wireshark packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"wireshark-0.99.4-EL4.1.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"wireshark-0.99.4-EL4.1.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"wireshark-gnome-0.99.4-EL4.1.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"wireshark-gnome-0.99.4-EL4.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

