#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-676.
#

include("compat.inc");

if (description)
{
  script_id(90269);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-3184", "CVE-2015-3187", "CVE-2015-5259", "CVE-2015-5343");
  script_xref(name:"ALAS", value:"2016-676");

  script_name(english:"Amazon Linux AMI : mod_dav_svn / subversion (ALAS-2016-676)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that when an SVN server (both svnserve and httpd with the
mod_dav_svn module) searched the history of a file or a directory, it
would disclose its location in the repository if that file or
directory was not readable (for example, if it had been moved).
(CVE-2015-3187)

An integer overflow was discovered allowing remote attackers to
execute arbitrary code via an svn:// protocol string, which triggers a
heap-based buffer overflow and an out-of-bounds read. (CVE-2015-5259)

It was found that the mod_authz_svn module did not properly restrict
anonymous access to Subversion repositories under certain
configurations when used with Apache httpd 2.4.x. This could allow a
user to anonymously access files in a Subversion repository, which
should only be accessible to authenticated users. (CVE-2015-3184)

It was found that the mod_dav_svn module was vulnerable to a remotely
triggerable heap-based buffer overflow and out-of-bounds read caused
by an integer overflow when parsing skel-encoded request bodies,
allowing an attacker with write access to a repository to cause a
denial of service attack (on 32-bit or 64-bit servers) or possibly
execute arbitrary code (on 32-bit servers only) under the context of
the httpd process. (CVE-2015-5343)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-676.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update mod_dav_svn' to update your system.

Run 'yum update subversion' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
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
if (rpm_check(release:"ALA", reference:"mod24_dav_svn-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-1.8.15-1.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-debuginfo-1.8.15-1.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python26-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python27-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.8.15-1.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.8.15-1.54.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod24_dav_svn / mod_dav_svn / mod_dav_svn-debuginfo / subversion / etc");
}
