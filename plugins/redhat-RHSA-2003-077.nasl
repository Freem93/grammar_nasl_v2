#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:077. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12373);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2003-0081", "CVE-2003-0159", "CVE-2003-0356", "CVE-2003-0357", "CVE-2003-0428", "CVE-2003-0429", "CVE-2003-0430", "CVE-2003-0431", "CVE-2003-0432");
  script_xref(name:"RHSA", value:"2003:077");

  script_name(english:"RHEL 2.1 : ethereal (RHSA-2003:077)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Ethereal packages fixing a number of remotely exploitable
security issues are now available.

Ethereal is a package designed for monitoring network traffic.

A number of security issues affect Ethereal. By exploiting these
issues it may be possible to make Ethereal crash or run arbitrary code
by injecting a purposefully malformed packet onto the wire, or by
convincing someone to read a malformed packet trace file.

Ethereal 0.9.9 and earlier allows remote attackers to cause a denial
of service (crash) and possibly execute arbitrary code via carefully
crafted SOCKS packets. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2003-0081 to this
issue.

A heap-based buffer overflow exists in the NTLMSSP code for Ethereal
0.9.9 and earlier. (CVE-2003-0159)

Multiple off-by-one vulnerabilities exist in Ethereal 0.9.11 and
earlier in the AIM, GIOP Gryphon, OSPF, PPTP, Quake, Quake2, Quake3,
Rsync, SMB, SMPP, and TSP dissectors, which do not properly use the
tvb_get_nstringz and tvb_get_nstringz0 functions. (CVE-2003-0356)

Multiple integer overflow vulnerabilities exist in Ethereal 0.9.11 and
earlier in the Mount and PPP dissectors. (CVE-2003-0357)

A vulnerability in the DCERPC dissector exists in Ethereal 0.9.12 and
earlier, allowing remote attackers to cause a denial of service
(memory consumption) via a certain NDR string. (CVE-2003-0428)

A possible buffer overflow vulnerability exists in Ethereal 0.9.12 and
earlier, caused by invalid IPv4 or IPv6 prefix lengths and possibly
triggering a buffer overflow. (CVE-2003-0429)

A vulnerability exists in Ethereal 0.9.12 and earlier, allowing remote
attackers to cause a denial of service (crash) via an invalid ASN.1
value. (CVE-2003-0430)

The tvb_get_nstringz0 function in Ethereal 0.9.12 and earlier does not
properly handle a zero-length buffer size. (CVE-2003-0431)

Ethereal 0.9.12 and earlier does not handle certain strings properly
in the BGP, WTP, DNS, 802.11, ISAKMP, WSP, CLNP, ISIS, and RMI
dissectors. (CVE-2003-0432)

Users of Ethereal should update to these erratum packages containing
Ethereal version 0.9.13, which are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0356.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0357.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0431.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0432.html"
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00008.html"
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00009.html"
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-077.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ethereal and / or ethereal-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2003:077";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ethereal-0.9.13-1.AS21.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ethereal-gnome-0.9.13-1.AS21.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ethereal / ethereal-gnome");
  }
}
