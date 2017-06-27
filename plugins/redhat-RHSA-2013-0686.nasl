# @DEPRECATED@
#
# Disabled on 2013/06/06.
#

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0686. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65904);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/02 20:36:57 $");

  script_cve_id("CVE-2012-6116", "CVE-2012-6119", "CVE-2013-0256", "CVE-2013-0263", "CVE-2013-0269", "CVE-2013-0276", "CVE-2013-1823");
  script_xref(name:"RHSA", value:"2013:0686");

  script_name(english:"RHEL 6 : Subscription Asset Manager (RHSA-2013:0686)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Subscription Asset Manager 1.2.1, which fixes several security
issues, multiple bugs, and adds various enhancements, is now
available.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Subscription Asset Manager acts as a proxy for handling
subscription information and software updates on client machines.

The latest packages for Subscription Asset Manager include a number of
security fixes :

When a Subscription Asset Manager instance is created, its
configuration script automatically creates an RPM of the internal
subscription service CA certificate. However, this RPM incorrectly
created the CA certificate with file permissions of 0666. This allowed
other users on a client system to modify the CA certificate used to
trust the remote subscription server. All administrators are advised
to update and deploy the subscription service certificate on all
systems which use Subscription Asset Manager as their subscription
service. This procedure is described in:
https://access.redhat.com/knowledge/docs/en-US/
Red_Hat_Subscription_Asset_Manager/1.2/html/Installation_Guide/
sect-Installation_Guide-Administration-Upgrading_Subscription_Asset_Ma
nager.html (CVE-2012-6116)

Manifest signature checking was not implemented for early versions of
Subscription Asset Manager. This meant that a malicious user could
edit a manifest file, insert arbitrary data, and successfully upload
the edited manifest file into the Subscription Asset Manager server.
(CVE-2012-6119)

Ruby's documentation generator had a flaw in the way it generated HTML
documentation. When a Ruby application exposed its documentation on a
network (such as a web page), an attacker could use a specially-
crafted URL to open an arbitrary web script or to execute HTML code
within the application's user session. (CVE-2013-0256)

A timing attack flaw was found in the way rubygem-rack and
ruby193-rubygem-rack processed HMAC digests in cookies. This flaw
could aid an attacker using forged digital signatures to bypass
authentication checks. (CVE-2013-0263)

A flaw in rubygem-json allowed remote attacks by creating different
types of malicious objects. For example, it could initiate a denial of
service (DoS) attack through resource consumption by using a JSON
document to create arbitrary Ruby symbols, which were never garbage
collected. It could also be exploited to create internal objects which
could allow a SQL injection attack. (CVE-2013-0269)

A flaw in ActiveRecord in Ruby on Rails allowed remote attackers to
circumvent attribute protections and to insert their own crafted
requests to change protected attribute values. (CVE-2013-0276)

HTML markup was not properly escaped when filling in the username
field in the Notifications form of the Subscription Asset Manager UI.
This meant that HTML code used in the value was then applied in the UI
page when the entry was viewed. This could have allowed malicious HTML
code to be entered. The field value is now validated and any HTML tags
are escaped. (CVE-2013-1823)

These updated packages also include bug fixes and enhancements :

* Previously, no SELinux policy for the subscription service was
included with the Subscription Asset Manager packages. The
candlepin-selinux package is now included with SELinux policies for
the subscription server. (BZ#906901)

* When attempting to use the subscription service's CA certificate to
validate a manifest during import, the comparison failed. The upstream
subscription service which generated the manifest is a different
service than the local subscription service; thus, they have different
CA certificates. This caused importing a manifest to fail with the
error 'archive failed signature'. This has been fixed so that the
proper certificate is used for verification. (BZ#918778)

All users of Subscription Asset Manager are recommended to update to
the latest packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6116.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6119.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0256.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0269.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0276.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0686.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-glue-candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-headpin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-headpin-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activemodel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-delayed_job");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-delayed_job-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rails_warden");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rails_warden-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thumbslug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thumbslug-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


# Deprecated
exit(0, "This plugin has been temporarily deprecated.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL6", reference:"candlepin-0.7.24-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"candlepin-devel-0.7.24-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"candlepin-selinux-0.7.24-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"candlepin-tomcat6-0.7.24-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-common-1.2.1.1-1h.el6_4")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-configure-1.2.3.1-4h.el6_4")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-glue-candlepin-1.2.1.1-1h.el6_4")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-headpin-1.2.1.1-1h.el6_4")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-headpin-all-1.2.1.1-1h.el6_4")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-nokogiri-1.5.0-0.9.beta4.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-actionpack-3.0.10-12.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-activemodel-3.0.10-3.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-activemodel-doc-3.0.10-3.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-delayed_job-2.1.4-3.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-delayed_job-doc-2.1.4-3.el6cf")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-1.7.3-2.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-debuginfo-1.7.3-2.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-nokogiri-1.5.0-0.9.beta4.el6cf")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-nokogiri-debuginfo-1.5.0-0.9.beta4.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-nokogiri-doc-1.5.0-0.9.beta4.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-rack-1.3.0-4.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-rails_warden-0.5.5-2.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-rails_warden-doc-0.5.5-2.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-rdoc-3.8-6.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-rdoc-doc-3.8-6.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"thumbslug-0.0.28.1-1.el6_4")) flag++;
if (rpm_check(release:"RHEL6", reference:"thumbslug-selinux-0.0.28.1-1.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
