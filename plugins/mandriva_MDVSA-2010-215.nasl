#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:215. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(50423);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:15:50 $");

  script_cve_id("CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450", "CVE-2010-3492", "CVE-2010-3493");
  script_bugtraq_id(40361, 40363, 40365, 43233, 44533);
  script_xref(name:"MDVSA", value:"2010:215");

  script_name(english:"Mandriva Linux Security Advisory : python (MDVSA-2010:215)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities was discovered and corrected in python :

Buffer underflow in the rgbimg module in Python 2.5 allows remote
attackers to cause a denial of service (application crash) via a large
ZSIZE value in a black-and-white (aka B/W) RGB image that triggers an
invalid pointer dereference (CVE-2009-4134).

Integer overflow in rgbimgmodule.c in the rgbimg module in Python 2.5
allows remote attackers to have an unspecified impact via a large
image that triggers a buffer overflow. NOTE: this vulnerability exists
because of an incomplete fix for CVE-2008-3143.12 (CVE-2010-1449).

Multiple buffer overflows in the RLE decoder in the rgbimg module in
Python 2.5 allow remote attackers to have an unspecified impact via an
image file containing crafted data that triggers improper processing
within the (1) longimagedata or (2) expandrow function
(CVE-2010-1450).

The asyncore module in Python before 3.2 does not properly handle
unsuccessful calls to the accept function, and does not have
accompanying documentation describing how daemon applications should
handle unsuccessful calls to the accept function, which makes it
easier for remote attackers to conduct denial of service attacks that
terminate these applications via network connections (CVE-2010-3492).

Multiple race conditions in smtpd.py in the smtpd module in Python
2.6, 2.7, 3.1, and 3.2 alpha allow remote attackers to cause a denial
of service (daemon outage) by establishing and then immediately
closing a TCP connection, leading to the accept function having an
unexpected return value of None, an unexpected value of None for the
address, or an ECONNABORTED, EAGAIN, or EWOULDBLOCK error, or the
getpeername function having an ENOTCONN error, a related issue to
CVE-2010-3492 (CVE-2010-3493).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter-apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64python2.5-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64python2.5-devel-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpython2.5-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpython2.5-devel-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"python-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"python-base-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"python-docs-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tkinter-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tkinter-apps-2.5.2-5.9mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
