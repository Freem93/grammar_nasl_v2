#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-454.
#

include("compat.inc");

if (description)
{
  script_id(79562);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-6407", "CVE-2014-6408");
  script_xref(name:"ALAS", value:"2014-454");

  script_name(english:"Amazon Linux AMI : docker (ALAS-2014-454)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Docker versions 1.3.0 through 1.3.1 allowed security options to be
applied to images, allowing images to modify the default run profile
of containers executing these images. This vulnerability could allow a
malicious image creator to loosen the restrictions applied to a
container's processes, potentially facilitating a break-out.
(CVE-2014-6408)

The Docker engine, up to and including version 1.3.1, was vulnerable
to extracting files to arbitrary paths on the host during 'docker
pull' and 'docker load' operations. This was caused by symlink and
hardlink traversals present in Docker's image extraction. This
vulnerability could be leveraged to perform remote code execution and
privilege escalation. (CVE-2014-6407)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-454.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update docker' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
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
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-1.3.2-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-devel-1.3.2-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-pkg-devel-1.3.2-1.0.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-devel / docker-pkg-devel");
}
