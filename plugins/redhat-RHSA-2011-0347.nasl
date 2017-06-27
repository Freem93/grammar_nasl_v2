
#
# (C) Tenable Network Security, Inc.
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(52628);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2011-0347: compat-openldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2011-0347");
 script_set_attribute(attribute: "description", value: '
  Updated openldap packages that fix three security issues are now available
  for Red Hat Enterprise Linux 6.

  The Red Hat Security Response Team has rated this update as having moderate
  security impact. Common Vulnerability Scoring System (CVSS) base scores,
  which give detailed severity ratings, are available for each vulnerability
  from the CVE links in the References section.

  OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  A flaw was found in the way OpenLDAP handled authentication failures being
  passed from an OpenLDAP slave to the master. If OpenLDAP was configured
  with a chain overlay and it forwarded authentication failures, OpenLDAP
  would bind to the directory as an anonymous user and return success, rather
  than return failure on the authenticated bind. This could allow a user on a
  system that uses LDAP for authentication to log into a directory-based
  account without knowing the password. (CVE-2011-1024)

  It was found that the OpenLDAP back-ndb back end allowed successful
  authentication to the root distinguished name (DN) when any string was
  provided as a password. A remote user could use this flaw to access an
  OpenLDAP directory if they knew the value of the root DN. Note: This issue
  only affected OpenLDAP installations using the NDB back-end, which is only
  available for Red Hat Enterprise Linux 6 via third-party software.
  (CVE-2011-1025)

  A flaw was found in the way OpenLDAP handled modify relative distinguished
  name (modrdn) requests. A remote, unauthenticated user could use this flaw
  to crash an OpenLDAP server via a modrdn request containing an empty old
  RDN value. (CVE-2011-1081)

  Users of OpenLDAP should upgrade to these updated packages, which contain
  backported patches to resolve these issues. After installing this update,
  the OpenLDAP daemons will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2011-0347.html");
script_set_attribute(attribute: "solution", value: "Update the affected package(s) using, for example, 'yum update'.");
script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/03/11");
 script_cvs_date("$Date: 2012/03/03 00:54:46 $");
script_end_attributes();

 script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
script_summary(english: "Check for the version of the compat-openldap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

flag = 0;

#if ( rpm_check( reference:"compat-openldap-2.4.19_2.3.43-15.el6_0.2", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"openldap-2.4.19-15.el6_0.2", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"openldap-clients-2.4.19-15.el6_0.2", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"openldap-debuginfo-2.4.19-15.el6_0.2", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"openldap-devel-2.4.19-15.el6_0.2", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"openldap-servers-2.4.19-15.el6_0.2", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"openldap-servers-sql-2.4.19-15.el6_0.2", release:'RHEL6') ) flag ++;
if (flag)
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
