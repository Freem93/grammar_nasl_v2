#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0360 and 
# Oracle Linux Security Advisory ELSA-2010-0360 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68032);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-2560", "CVE-2009-2562", "CVE-2009-2563", "CVE-2009-3550", "CVE-2009-3829", "CVE-2009-4377", "CVE-2010-0304");
  script_bugtraq_id(35748, 36591, 36846, 37407, 37985);
  script_xref(name:"RHSA", value:"2010:0360");

  script_name(english:"Oracle Linux 3 / 4 / 5 : wireshark (ELSA-2010-0360)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0360 :

Updated wireshark packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

An invalid pointer dereference flaw was found in the Wireshark SMB and
SMB2 dissectors. If Wireshark read a malformed packet off a network or
opened a malicious dump file, it could crash or, possibly, execute
arbitrary code as the user running Wireshark. (CVE-2009-4377)

Several buffer overflow flaws were found in the Wireshark LWRES
dissector. If Wireshark read a malformed packet off a network or
opened a malicious dump file, it could crash or, possibly, execute
arbitrary code as the user running Wireshark. (CVE-2010-0304)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2009-2560,
CVE-2009-2562, CVE-2009-2563, CVE-2009-3550, CVE-2009-3829)

Users of Wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.11, and resolve these issues. All
running instances of Wireshark must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-April/001441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-April/001442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-April/001443.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"wireshark-1.0.11-0.1.EL3.6")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"wireshark-1.0.11-0.1.EL3.6")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"wireshark-gnome-1.0.11-0.1.EL3.6")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"wireshark-gnome-1.0.11-0.1.EL3.6")) flag++;

if (rpm_check(release:"EL4", reference:"wireshark-1.0.11-1.0.1.el4_8.5")) flag++;
if (rpm_check(release:"EL4", reference:"wireshark-gnome-1.0.11-1.0.1.el4_8.5")) flag++;

if (rpm_check(release:"EL5", reference:"wireshark-1.0.11-1.0.1.el5_5.5")) flag++;
if (rpm_check(release:"EL5", reference:"wireshark-gnome-1.0.11-1.0.1.el5_5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
}
