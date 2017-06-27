#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-461.
#

include("compat.inc");

if (description)
{
  script_id(79875);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-9356", "CVE-2014-9357", "CVE-2014-9358");
  script_xref(name:"ALAS", value:"2014-461");

  script_name(english:"Amazon Linux AMI : docker (ALAS-2014-461)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Path traversal attacks are possible in the processing of absolute
symlinks. In checking symlinks for traversals, only relative links
were considered. This allowed path traversals to exist where they
should have otherwise been prevented. This was exploitable via both
archive extraction and through volume mounts. This vulnerability
allowed malicious images or builds from malicious Dockerfiles to write
files to the host system and escape containerization, leading to
privilege escalation. (CVE-2014-9356)

It has been discovered that the introduction of chroot for archive
extraction in Docker 1.3.2 had introduced a privilege escalation
vulnerability. Malicious images or builds from malicious Dockerfiles
could escalate privileges and execute arbitrary code as a root user on
the Docker host by providing a malicious 'xz' binary. (CVE-2014-9357)

It has been discovered that Docker does not sufficiently validate
Image IDs as provided either via 'docker load' or through registry
communications. This allows for path traversal attacks, causing graph
corruption and manipulation by malicious images, as well as repository
spoofing attacks. (CVE-2014-9358)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-461.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update docker' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-1.3.3-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-devel-1.3.3-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-pkg-devel-1.3.3-1.0.amzn1")) flag++;

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
