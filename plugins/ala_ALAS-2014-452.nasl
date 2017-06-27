#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-452.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79560);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1995", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2064", "CVE-2013-2066");
  script_xref(name:"ALAS", value:"2014-452");
  script_xref(name:"RHSA", value:"2014:1436");

  script_name(english:"Amazon Linux AMI : libX11 / libXcursor,libXfixes,libXi,libXrandr,libXrender,libXres,libXt,libXv,libXvMC,libXxf86dga,libXxf86vm,libdmx,xorg-x11-proto-devel (ALAS-2014-452)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way various X11 client libraries handled
certain protocol data. An attacker able to submit invalid protocol
data to an X11 server via a malicious X11 client could use either of
these flaws to potentially escalate their privileges on the system.
(CVE-2013-1981 , CVE-2013-1982 , CVE-2013-1983 , CVE-2013-1984 ,
CVE-2013-1985 , CVE-2013-1986 , CVE-2013-1987 , CVE-2013-1988 ,
CVE-2013-1989 , CVE-2013-1990 , CVE-2013-1991 , CVE-2013-2003 ,
CVE-2013-2062 , CVE-2013-2064)

Multiple array index errors, leading to heap-based buffer
out-of-bounds write flaws, were found in the way various X11 client
libraries handled data returned from an X11 server. A malicious X11
server could possibly use this flaw to execute arbitrary code with the
privileges of the user running an X11 client. (CVE-2013-1997 ,
CVE-2013-1998 , CVE-2013-1999 , CVE-2013-2000 , CVE-2013-2001 ,
CVE-2013-2002 , CVE-2013-2066)

A buffer overflow flaw was found in the way the XListInputDevices()
function of X.Org X11's libXi runtime library handled signed numbers.
A malicious X11 server could possibly use this flaw to execute
arbitrary code with the privileges of the user running an X11 client.
(CVE-2013-1995)

A flaw was found in the way the X.Org X11 libXt runtime library used
uninitialized pointers. A malicious X11 server could possibly use this
flaw to execute arbitrary code with the privileges of the user running
an X11 client. (CVE-2013-2005)

Two stack-based buffer overflow flaws were found in the way libX11,
the Core X11 protocol client library, processed certain user-specified
files. A malicious X11 server could possibly use this flaw to crash an
X11 client via a specially crafted file. (CVE-2013-2004)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-452.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update libX11 libXcursor libXfixes libXi libXrandr libXrender
libXres libXt libXv libXvMC libXxf86dga libXxf86vm libdmx
xorg-x11-proto-devel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXcursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfixes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXrandr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXrender-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXres-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXvMC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXxf86dga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXxf86dga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXxf86dga-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXxf86vm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXxf86vm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libdmx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libdmx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"libX11-1.6.0-2.2.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libX11-common-1.6.0-2.2.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libX11-debuginfo-1.6.0-2.2.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libX11-devel-1.6.0-2.2.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXcursor-1.1.14-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXcursor-debuginfo-1.1.14-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXcursor-devel-1.1.14-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXfixes-5.0.1-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXfixes-debuginfo-5.0.1-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXfixes-devel-5.0.1-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXi-1.7.2-2.2.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXi-debuginfo-1.7.2-2.2.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXi-devel-1.7.2-2.2.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXrandr-1.4.1-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXrandr-debuginfo-1.4.1-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXrandr-devel-1.4.1-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXrender-0.9.8-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXrender-debuginfo-0.9.8-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXrender-devel-0.9.8-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXres-1.0.7-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXres-debuginfo-1.0.7-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXres-devel-1.0.7-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXt-1.1.4-6.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXt-debuginfo-1.1.4-6.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXt-devel-1.1.4-6.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXv-1.0.9-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXv-debuginfo-1.0.9-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXv-devel-1.0.9-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXvMC-1.0.8-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXvMC-debuginfo-1.0.8-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXvMC-devel-1.0.8-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXxf86dga-1.1.4-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXxf86dga-debuginfo-1.1.4-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXxf86dga-devel-1.1.4-2.1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXxf86vm-1.1.3-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXxf86vm-debuginfo-1.1.3-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXxf86vm-devel-1.1.3-2.1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libdmx-1.1.3-3.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libdmx-debuginfo-1.1.3-3.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libdmx-devel-1.1.3-3.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-proto-devel-7.7-9.10.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11 / libX11-common / libX11-debuginfo / libX11-devel / etc");
}
