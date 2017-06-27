#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-635.
#

include("compat.inc");

if (description)
{
  script_id(87969);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/01/19 15:00:09 $");

  script_cve_id("CVE-2015-5292");
  script_xref(name:"ALAS", value:"2016-635");

  script_name(english:"Amazon Linux AMI : sssd (ALAS-2016-635)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that SSSD's Privilege Attribute Certificate (PAC)
responder plug-in would leak a small amount of memory on each
authentication request. A remote attacker could potentially use this
flaw to exhaust all available memory on the system by making repeated
requests to a Kerberized daemon application configured to authenticate
using the PAC responder plug-in."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-635.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update sssd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"libipa_hbac-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libipa_hbac-devel-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_idmap-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_idmap-devel-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_nss_idmap-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_nss_idmap-devel-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_simpleifp-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_simpleifp-devel-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libipa_hbac-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libsss_nss_idmap-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-sss-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-sss-murmur-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-sssdconfig-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-ad-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-client-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-common-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-common-pac-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-dbus-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-debuginfo-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-ipa-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-krb5-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-krb5-common-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-ldap-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-libwbclient-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-libwbclient-devel-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-proxy-1.13.0-40.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-tools-1.13.0-40.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_idmap / libsss_idmap-devel / etc");
}
