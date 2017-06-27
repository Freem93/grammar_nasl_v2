#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0087.
#

include("compat.inc");

if (description)
{
  script_id(91800);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449");
  script_osvdb_id(130651, 130653, 134833, 136114, 136194, 137962, 138565, 138566, 138567, 138568, 138569, 138570, 138571, 138572, 138926, 138928, 138966);

  script_name(english:"OracleVM 3.3 / 3.4 : libxml2 (OVMSA-2016-0087)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Update doc/redhat.gif in tarball

  - Add libxml2-oracle-enterprise.patch and update logos in
    tarball

  - Heap-based buffer overread in xmlNextChar
    (CVE-2016-1762)

  - Bug 763071: Heap-buffer-overflow in xmlStrncat
    (CVE-2016-1834)

  - Bug 757711: Heap-buffer-overflow in
    xmlFAParsePosCharGroup (CVE-2016-1840)

  - Bug 758588: Heap-based buffer overread in
    xmlParserPrintFileContextInternal (CVE-2016-1838)

  - Bug 758605: Heap-based buffer overread in
    xmlDictAddString (CVE-2016-1839)

  - Bug 759398: Heap use-after-free in xmlDictComputeFastKey
    (CVE-2016-1836)

  - Fix inappropriate fetch of entities content
    (CVE-2016-4449)

  - Heap use-after-free in htmlParsePubidLiteral and
    htmlParseSystemiteral (CVE-2016-1837)

  - Heap use-after-free in xmlSAX2AttributeNs
    (CVE-2016-1835)

  - Heap-based buffer-underreads due to xmlParseName
    (CVE-2016-4447)

  - Heap-based buffer overread in htmlCurrentChar
    (CVE-2016-1833)

  - Add missing increments of recursion depth counter to XML
    parser. (CVE-2016-3705)

  - Avoid building recursive entities (CVE-2016-3627)

  - Fix some format string warnings with possible format
    string vulnerability (CVE-2016-4448)

  - More format string warnings with possible format string
    vulnerability (CVE-2016-4448)

  - Fix large parse of file from memory (rhbz#862969)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=757711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=758588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=758605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=759398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000501.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 / libxml2-python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"libxml2-2.7.6-21.0.1.el6_8.1")) flag++;
if (rpm_check(release:"OVS3.3", reference:"libxml2-python-2.7.6-21.0.1.el6_8.1")) flag++;

if (rpm_check(release:"OVS3.4", reference:"libxml2-2.7.6-21.0.1.el6_8.1")) flag++;
if (rpm_check(release:"OVS3.4", reference:"libxml2-python-2.7.6-21.0.1.el6_8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-python");
}
