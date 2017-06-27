#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:119. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82372);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2015-0255");
  script_xref(name:"MDVSA", value:"2015:119");

  script_name(english:"Mandriva Linux Security Advisory : x11-server (MDVSA-2015:119)");
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
"Updated x11-server packages fix security vulnerabilities :

Ilja van Sprundel of IOActive discovered several security issues in
the X.org X server, which may lead to privilege escalation or denial
of service (CVE-2014-8091, CVE-2014-8092, CVE-2014-8093,
CVE-2014-8094, CVE-2014-8095, CVE-2014-8096, CVE-2014-8097,
CVE-2014-8098, CVE-2014-8099, CVE-2014-8100, CVE-2014-8101,
CVE-2014-8102).

Olivier Fourdan from Red Hat has discovered a protocol handling issue
in the way the X server code base handles the XkbSetGeometry request,
where the server trusts the client to send valid string lengths. A
malicious client with string lengths exceeding the request length can
cause the server to copy adjacent memory data into the XKB structs.
This data is then available to the client via the XkbGetGeometry
request. This can lead to information disclosure issues, as well as
possibly a denial of service if a similar request can cause the server
to crash (CVE-2015-0255)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0532.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0073.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xfake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xfbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-common-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-devel-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"x11-server-source-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-xdmx-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-xephyr-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-xfake-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-xfbdev-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-xnest-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-xorg-1.14.5-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"x11-server-xvfb-1.14.5-3.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
