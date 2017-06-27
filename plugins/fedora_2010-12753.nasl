#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-12753.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48329);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_bugtraq_id(42391);
  script_xref(name:"FEDORA", value:"2010-12753");

  script_name(english:"Fedora 13 : drupal-6.19-1.fc13 (2010-12753)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"DRUPAL-SA-CORE-2010-002 Remember to log in to your site as the admin
user before upgrading this package. After upgrading the package,
browse to http://host/drupal/update.php to run the upgrade script, for
each site. * Advisory ID: DRUPAL-SA-CORE-2010-002 * Project: Drupal
core * Version: 5.x, 6.x * Date: 2010-August-11 * Security risk:
Critical * Exploitable from: Remote * Vulnerability: Multiple
vulnerabilities -------- DESCRIPTION
--------------------------------------------------------- Multiple
vulnerabilities and weaknesses were discovered in Drupal. .... OpenID
authentication bypass The OpenID module provides users the ability to
login to sites using an OpenID account. The OpenID module doesn't
implement all the required verifications from the OpenID 2.0 protocol
and is vulnerable to a number of attacks. Specifically: - OpenID
should verify that a 'openid.response_nonce' has not already been used
for an assertion by the OpenID provider - OpenID should verify the
value of openid.return_to as obtained from the OpenID provider -
OpenID must verify that all fields that are required to be signed are
signed These specification violations allow malicious sites to harvest
positive assertions from OpenID providers and use them on sites using
the OpenID module to obtain access to preexisting accounts bound to
the harvested OpenIDs. Intercepted assertions from OpenID providers
can also be replayed and used to obtain access to user accounts bound
to the intercepted OpenIDs. This issue affects Drupal 6.x only. A
separate security announcement and release [1] is published for the
contributed OpenID module for Drupal 5.x. .... File download access
bypass The upload module allows users to upload files and provides
access checking for file downloads. The module looks up files for
download in the database and serves them for download after access
checking. However, it does not account for the fact that certain
database configurations will not consider case differences in file
names. If a malicious user uploads a file which only differs in letter
case, access will be granted for the earlier upload regardless of
actual file access to that. This issue affects Drupal 5.x and 6.x.
.... Comment unpublishing bypass The comment module allows users to
leave comments on content on the site. The module supports
unpublishing comments by privileged users. Users with the 'post
comments without approval' permission however could craft a URL which
allows them to republish previously unpublished comments. This issue
affects Drupal 5.x and 6.x. .... Actions cross site scripting The
actions feature combined with Drupal's trigger module allows users to
configure certain actions to happen when users register, content is
submitted, and so on; through a web-based interface. Users with
'administer actions permission' can enter action descriptions and
messages which are not properly filtered on output. Users with content
and taxonomy tag submission permissions can create nodes and taxonomy
terms which are not properly sanitized for inclusion in action
messages and inject arbitrary HTML and script code into Drupal pages.
Such a cross-site scripting attack may lead to the malicious user
gaining administrative access. Wikipedia has more information about
cross-site scripting [2] (XSS). This issue affects Drupal 6.x only.
-------- VERSIONS AFFECTED
--------------------------------------------------- * Drupal 6.x
before version 6.18 or 6.19. * Drupal 5.x before version 5.23.
-------- SOLUTION
------------------------------------------------------------ Install
the latest version: * If you are running Drupal 6.x then upgrade to
Drupal 6.18 [3] or Drupal 6.19 [4]. * If you are running Drupal 5.x
then upgrade to Drupal 5.23 [5]. Drupal 5 will no longer be maintained
when Drupal 7 is released [6]. Upgrading to Drupal 6 [7] is
recommended. The security team starts a new practice of releasing both
a pure security update without other bugfixes and a security update
combined with other bug fixes and improvements. You can choose to
either only include the security update for an immediate fix (which
might require less quality assurance and testing) or more fixes and
improvements alongside the security fixes by choosing between Drupal
6.18 and Drupal 6.19. Read the announcement [8] for more information.
-------- REPORTED BY
--------------------------------------------------------- The OpenID
authentication bypass issues were reported by Johnny Bufu [9],
Christian Schmidt [10] and Heine Deelstra [11] (*). The file download
access bypass was reported by Dylan Tack [12] (*). The comment
unpublish bypass issue was reported by Heine Deelstra [13] (*). The
actions module cross site scripting was reported by Justin Klein Keane
[14] and Heine Deelstra [15] (*). (*) Member of the Drupal security
team. -------- FIXED BY
------------------------------------------------------------ The
OpenID authentication issues were fixed by Christian Schmidt [16],
Heine Deelstra [17] (*) and Damien Tournoud [18] (*). The file
download access bypass was fixed by Dave Reid [19] (*) and Neil Drumm
[20] (*). The comment unpublish bypass issue was fixed by Heine
Deelstra [21] (*). The actions module cross site scripting was fixed
by Justin Klein Keane [22] and Heine Deelstra [23] (*). (*) Member of
the Drupal security team. -------- CONTACT
------------------------------------------------------------- The
security team for Drupal can be reached at security at drupal.org or
via the form at http://drupal.org/contact. [1]
http://drupal.org/node/880480 [2]
http://en.wikipedia.org/wiki/Cross-site_scripting [3]
http://ftp.drupal.org/files/projects/drupal-6.18.tar.gz [4]
http://ftp.drupal.org/files/projects/drupal-6.19.tar.gz [5]
http://ftp.drupal.org/files/projects/drupal-5.23.tar.gz [6]
http://drupal.org/node/725382 [7] http://drupal.org/upgrade [8]
http://drupal.org/drupal-6.19 [9] http://drupal.org/user/226462 [10]
http://drupal.org/user/216078 [11] http://drupal.org/user/17943 [12]
http://drupal.org/user/96647 [13] http://drupal.org/user/17943 [14]
http://drupal.org/user/302225 [15] http://drupal.org/user/17943 [16]
http://drupal.org/user/216078 [17] http://drupal.org/user/17943 [18]
http://drupal.org/user/22211 [19] http://drupal.org/user/53892 [20]
http://drupal.org/user/3064 [21] http://drupal.org/user/17943 [22]
http://drupal.org/user/302225 [23] http://drupal.org/user/17943
_______________________________________________ Security-news mailing
list Security-news at drupal.org
http://lists.drupal.org/mailman/listinfo/security-news

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/drupal-6.19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/725382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/880480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/upgrade"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Cross-site_scripting"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.drupal.org/files/projects/drupal-5.23.tar.gz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.drupal.org/files/projects/drupal-6.18.tar.gz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.drupal.org/files/projects/drupal-6.19.tar.gz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.drupal.org/mailman/listinfo/security-news"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/045464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f903ee21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"drupal-6.19-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal");
}
