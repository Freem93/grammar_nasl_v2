#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1417 and 
# CentOS Errata and Security Advisory 2015:1417 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85018);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/28 16:58:13 $");

  script_cve_id("CVE-2002-0389", "CVE-2015-2775");
  script_bugtraq_id(4538, 73922);
  script_osvdb_id(5309, 120120);
  script_xref(name:"RHSA", value:"2015:1417");

  script_name(english:"CentOS 6 : mailman (CESA-2015:1417)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mailman packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mailman is a program used to help manage e-mail discussion lists.

It was found that mailman did not sanitize the list name before
passing it to certain MTAs. A local attacker could use this flaw to
execute arbitrary code as the user running mailman. (CVE-2015-2775)

It was found that mailman stored private email messages in a
world-readable directory. A local user could use this flaw to read
private mailing list archives. (CVE-2002-0389)

This update also fixes the following bugs :

* Previously, it was impossible to configure Mailman in a way that
Domain-based Message Authentication, Reporting & Conformance (DMARC)
would recognize Sender alignment for Domain Key Identified Mail (DKIM)
signatures. Consequently, Mailman list subscribers that belonged to a
mail server with a 'reject' policy for DMARC, such as yahoo.com or
AOL.com, were unable to receive Mailman forwarded messages from
senders residing in any domain that provided DKIM signatures. With
this update, domains with a 'reject' DMARC policy are recognized
correctly, and Mailman list administrators are able to configure the
way these messages are handled. As a result, after a proper
configuration, subscribers now correctly receive Mailman forwarded
messages in this scenario. (BZ#1095359)

* Mailman used a console encoding when generating a subject for a
'welcome email' when new mailing lists were created by the 'newlist'
command. Consequently, when the console encoding did not match the
encoding used by Mailman for that particular language, characters in
the 'welcome email' could be displayed incorrectly. Mailman has been
fixed to use the correct encoding, and characters in the 'welcome
email' are now displayed properly. (BZ#1056366)

* The 'rmlist' command used a hard-coded path to list data based on
the VAR_PREFIX configuration variable. As a consequence, when the list
was created outside of VAR_PREFIX, it was impossible to remove it
using the 'rmlist' command. With this update, the 'rmlist' command
uses the correct LIST_DATA_DIR value instead of VAR_PREFIX, and it is
now possible to remove the list in described situation. (BZ#1008139)

* Due to an incompatibility between Python and Mailman in Red Hat
Enterprise Linux 6, when moderators were approving a moderated message
to a mailing list and checked the 'Preserve messages for the site
administrator' checkbox, Mailman failed to approve the message and
returned an error. This incompatibility has been fixed, and Mailman
now approves messages as expected in this scenario. (BZ#765807)

* When Mailman was set to not archive a list but the archive was not
set to private, attachments sent to that list were placed in a public
archive. Consequently, users of Mailman web interface could list
private attachments because httpd configuration of public archive
directory allows listing all files in the archive directory. The httpd
configuration of Mailman has been fixed to not allow listing of
private archive directory, and users of Mailman web interface are no
longer able to list private attachments. (BZ#745409)

Users of mailman are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09c9ea6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"mailman-2.1.12-25.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
