#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:074. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66088);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2012-1588",
    "CVE-2012-1589",
    "CVE-2012-1590",
    "CVE-2012-1591",
    "CVE-2012-2153",
    "CVE-2012-2922",
    "CVE-2012-5651",
    "CVE-2012-5653"
  );
  script_bugtraq_id(
    53359,
    53362,
    53365,
    53368,
    53454,
    56993
  );
  script_osvdb_id(
    81678,
    81679,
    81680,
    81681,
    81682,
    81817,
    88528,
    88529
  );
  script_xref(name:"MDVSA", value:"2013:074");
  script_xref(name:"MGASA", value:"2012-0320");
  script_xref(name:"MGASA", value:"2012-0366");
  script_xref(name:"MGASA", value:"2013-0027");

  script_name(english:"Mandriva Linux Security Advisory : drupal (MDVSA-2013:074)");
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
"Updated drupal packages fix security vulnerabilities :

Drupal core's text filtering system provides several features
including removing inappropriate HTML tags and automatically linking
content that appears to be a link. A pattern in Drupal's text matching
was found to be inefficient with certain specially crafted strings.
This vulnerability is mitigated by the fact that users must have the
ability to post content sent to the filter system such as a role with
the post comments or Forum topic: Create new content permission
(CVE-2012-1588).

Drupal core's Form API allows users to set a destination, but failed
to validate that the URL was internal to the site. This weakness could
be abused to redirect the login to a remote site with a malicious
script that harvests the login credentials and redirects to the live
site. This vulnerability is mitigated only by the end user's ability
to recognize a URL with malicious query parameters to avoid the social
engineering required to exploit the problem (CVE-2012-1589).

Drupal core's forum lists fail to check user access to nodes when
displaying them in the forum overview page. If an unpublished node was
the most recently updated in a forum then users who should not have
access to unpublished forum posts were still be able to see meta-data
about the forum post such as the post title (CVE-2012-1590).

Drupal core provides the ability to have private files, including
images, and Image Styles which create derivative images from an
original image that may differ, for example, in size or saturation.
Drupal core failed to properly terminate the page request for cached
image styles allowing users to access image derivatives for images
they should not be able to view. Furthermore, Drupal didn't set the
right headers to prevent image styles from being cached in the browser
(CVE-2012-1591).

Drupal core provides the ability to list nodes on a site at
admin/content. Drupal core failed to confirm a user viewing that page
had access to each node in the list. This vulnerability only concerns
sites running a contributed node access module and is mitigated by the
fact that users must have a role with the Access the content overview
page permission. Unpublished nodes were not displayed to users who
only had the Access the content overview page permission
(CVE-2012-2153).

The request_path function in includes/bootstrap.inc in Drupal 7.14 and
earlier allows remote attackers to obtain sensitive information via
the q[] parameter to index.php, which reveals the installation path in
an error message (CVE-2012-2922).

A bug in the installer code was identified that allows an attacker to
re-install Drupal using an external database server under certain
transient conditions. This could allow the attacker to execute
arbitrary PHP code on the original server (Drupal SA-CORE-2012-003).

For sites using the core OpenID module, an information disclosure
vulnerability was identified that allows an attacker to read files on
the local filesystem by attempting to log in to the site using a
malicious OpenID server (Drupal SA-CORE-2012-003).

A vulnerability was identified that allows blocked users to appear in
user search results, even when the search results are viewed by
unprivileged users (CVE-2012-5651).

Drupal core's file upload feature blocks the upload of many files that
can be executed on the server by munging the filename. A malicious
user could name a file in a manner that bypasses this munging of the
filename in Drupal's input validation (CVE-2012-5653).

Multiple vulnerabilities were fixed in the supported Drupal core
version 7 (DRUPAL-SA-CORE-2013-001).

A reflected cross-site scripting vulnerability (XSS) was identified in
certain Drupal JavaScript functions that pass unexpected user input
into jQuery causing it to insert HTML into the page when the intended
behavior is to select DOM elements. Multiple core and contributed
modules are affected by this issue.

A vulnerability was identified that exposes the title or, in some
cases, the content of nodes that the user should not have access to.

Drupal core provides the ability to have private files, including
images. A vulnerability was identified in which derivative images
(which Drupal automatically creates from these images based on image
styles and which may differ, for example, in size or saturation) did
not always receive the same protection. Under some circumstances, this
would allow users to access image derivatives for images they should
not be able to view.

The drupal package was updated to latest version 7.19 to fix above
vulnerabilities."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"drupal-7.19-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-mysql-7.19-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-postgresql-7.19-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-sqlite-7.19-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
