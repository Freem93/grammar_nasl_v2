#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0012.
#

include("compat.inc");

if (description)
{
  script_id(79459);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2009-0946");
  script_bugtraq_id(29637, 29639, 29640, 29641, 34550);

  script_name(english:"OracleVM 2.1 : freetype (OVMSA-2009-0012)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

CVE-2009-0946 Multiple integer overflows in FreeType 2.3.9 and earlier
allow remote attackers to execute arbitrary code via vectors related
to large values in certain inputs in (1) smooth/ftsmooth.c, (2)
sfnt/ttcmap.c, and (3) cff/cffload.c.

CVE-2008-1806 Integer overflow in FreeType2 before 2.3.6 allows
context-dependent attackers to execute arbitrary code via a crafted
set of 16-bit length values within the Private dictionary table in a
Printer Font Binary (PFB) file, which triggers a heap-based buffer
overflow.

CVE-2008-1807 FreeType2 before 2.3.6 allow context-dependent attackers
to execute arbitrary code via an invalid 'number of axes' field in a
Printer Font Binary (PFB) file, which triggers a free of arbitrary
memory locations, leading to memory corruption.

CVE-2008-1808 Multiple off-by-one errors in FreeType2 before 2.3.6
allow context-dependent attackers to execute arbitrary code via (1) a
crafted table in a Printer Font Binary (PFB) file or (2) a crafted SHC
instruction in a TrueType Font (TTF) file, which triggers a heap-based
buffer overflow.

  - Add freetype-2009-CVEs.patch

  - Resolves: #496111

  - Add freetype-2.3.5-CVEs.patch

  - Resolves: #450910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2009-May/000026.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"freetype-2.2.1-21.el5_3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");
}
