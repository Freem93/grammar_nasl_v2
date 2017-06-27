#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-461.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21294);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:46:27 $");

  script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
  script_xref(name:"FEDORA", value:"2006-461");

  script_name(english:"Fedora Core 4 : ethereal-0.99.0-fc4.1 (2006-461)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Many security vulnerabilities have been fixed since the previous
release.

  - The H.248 dissector could crash. Versions affected:
    0.10.14. CVE: CVE-2006-1937

  - The UMA dissector could go into an infinite loop.
    Versions affected: 0.10.12 - 0.10.14. CVE: CVE-2006-1933

  - The X.509if dissector could crash. Versions affected:
    0.10.14. CVE: CVE-2006-1937

  - The SRVLOC dissector could crash. Versions affected:
    0.10.0 - 0.10.14. CVE: CVE-2006-1937

  - The H.245 dissector could crash. Versions affected:
    0.10.13 - 0.10.14. CVE: CVE-2006-1937

  - Ethereal's OID printing routine was susceptible to an
    off-by-one error. Versions affected: 0.10.14. CVE:
    CVE-2006-1932

  - The COPS dissector could overflow a buffer. Versions
    affected: 0.9.15 - 0.10.14. CVE: CVE-2006-1935

  - The ALCAP dissector could overflow a buffer. Versions
    affected: 0.10.14. CVE: CVE-2006-1934

Under a grant funded by the U.S. Department of Homeland Security,
Coverity has uncovered a number of vulnerabilities in Ethereal :

  - The statistics counter could crash Ethereal. Versions
    affected: 0.10.10 - 0.10.14. CVE: CVE-2006-1937

  - Ethereal could crash while reading a malformed Sniffer
    capture. Versions affected: 0.8.12 - 0.10.14. CVE:
    CVE-2006-1938

  - An invalid display filter could crash Ethereal. Versions
    affected: 0.9.16 - 0.10.14. CVE: CVE-2006-1939

  - The general packet dissector could crash Ethereal.
    Versions affected: 0.10.9 - 0.10.14. CVE: CVE-2006-1937

  - The AIM dissector could crash Ethereal. Versions
    affected: 0.10.7 - 0.10.14. CVE: CVE-2006-1937

  - The RPC dissector could crash Ethereal. Versions
    affected: 0.9.8 - 0.10.14. CVE: CVE-2006-1939

  - The DCERPC dissector could crash Ethereal. Versions
    affected: 0.9.16 - 0.10.14. CVE: CVE-2006-1939

  - The ASN.1 dissector could crash Ethereal. Versions
    affected: 0.9.8 - 0.10.14. CVE: CVE-2006-1939

  - The SMB PIPE dissector could crash Ethereal. Versions
    affected: 0.8.20 - 0.10.14. CVE: CVE-2006-1938

  - The BER dissector could loop excessively. Versions
    affected: 0.10.4 - 0.10.14. CVE: CVE-2006-1933

  - The SNDCP dissector could abort. Versions affected:
    0.10.4 - 0.10.14. CVE: CVE-2006-1940

  - The Network Instruments file code could overrun a
    buffer. Versions affected: 0.10.0 - 0.10.14. CVE:
    CVE-2006-1934

  - The NetXray/Windows Sniffer file code could overrun a
    buffer. Versions affected: 0.10.13 - 0.10.14. CVE:
    CVE-2006-1934

  - The GSM SMS dissector could crash Ethereal. Versions
    affected: 0.9.16 - 0.10.14. CVE: CVE-2006-1939

  - The ALCAP dissector could overrun a buffer. Versions
    affected: 0.10.14. CVE: CVE-2006-1934

  - The telnet dissector could overrun a buffer. Versions
    affected: 0.8.5 - 0.10.14. CVE: CVE-2006-1936

  - ASN.1-based dissectors could crash Ethereal. Versions
    affected: 0.9.10 - 0.10.14. CVE: CVE-2006-1939

  - The H.248 dissector could crash Ethereal. Versions
    affected: 0.10.11 - 0.10.14. CVE: CVE-2006-1937

  - The DCERPC NT dissector could crash Ethereal. Versions
    affected: 0.9.14 - 0.10.14. CVE: CVE-2006-1939

  - The PER dissector could crash Ethereal. Versions
    affected: 0.9.14 - 0.10.14. CVE: CVE-2006-1939

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-April/002158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbd47a84"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected ethereal, ethereal-debuginfo and / or
ethereal-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"ethereal-0.99.0-fc4.1")) flag++;
if (rpm_check(release:"FC4", reference:"ethereal-debuginfo-0.99.0-fc4.1")) flag++;
if (rpm_check(release:"FC4", reference:"ethereal-gnome-0.99.0-fc4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ethereal / ethereal-debuginfo / ethereal-gnome");
}
